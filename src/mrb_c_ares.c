#include "mrb_c_ares.h"

static void
mrb_ares_state_callback(void *data, ares_socket_t socket_fd, int readable, int writable)
{
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) data;
  if (mrb_cares_ctx->destruction)
    return;
  mrb_state *mrb = mrb_cares_ctx->mrb;
  int arena_index = mrb_gc_arena_save(mrb);

  struct mrb_jmpbuf* prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;

  MRB_TRY(&c_jmp)
  {
    mrb->jmp = &c_jmp;
    mrb_value argv[] = {mrb_int_value(mrb, socket_fd), mrb_bool_value(readable), mrb_bool_value(writable)};
    mrb_yield_argv(mrb, mrb_cares_ctx->block, NELEMS(argv), argv);
    mrb->jmp = prev_jmp;
  }
  MRB_CATCH(&c_jmp)
  {
    mrb->jmp = prev_jmp;
  }
  MRB_END_EXC(&c_jmp);

  mrb_gc_arena_restore(mrb, arena_index);
}

static mrb_value
mrb_cares_get_ai(mrb_state *mrb, struct mrb_cares_args *mrb_cares_args, struct ares_addrinfo_node *node)
{
  mrb_value argv[] = {
    mrb_str_new(mrb_cares_args->mrb_cares_ctx->mrb, (const char *) node->ai_addr, node->ai_addrlen),
    mrb_int_value(mrb, node->ai_family),
    mrb_int_value(mrb, node->ai_socktype),
    mrb_int_value(mrb, node->ai_protocol)
  };

  return mrb_obj_new(mrb_cares_args->mrb_cares_ctx->mrb, mrb_cares_args->mrb_cares_ctx->addrinfo_class, NELEMS(argv), argv);
}

static void 
mrb_ares_getaddrinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *result)
{
  struct mrb_cares_args *mrb_cares_args = (struct mrb_cares_args *) arg;
  if (ARES_EDESTRUCTION == status)
    return;

  mrb_state *mrb = mrb_cares_args->mrb_cares_ctx->mrb;
  struct mrb_jmpbuf* prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;

  MRB_TRY(&c_jmp)
  {
    mrb->jmp = &c_jmp;
    mrb_value argv[4] = {mrb_nil_value()};
    argv[0] = mrb_int_value(mrb, timeouts);
    if (likely(ARES_SUCCESS == status)) {
      struct ares_addrinfo_cname *cname = result->cnames;
      if (cname) {
        argv[1] = mrb_ary_new_capa(mrb, 1);
        do {
          mrb_ary_push(mrb, argv[1], mrb_str_new_cstr(mrb, cname->name));
        } while ((cname = cname->next));
      }
      struct ares_addrinfo_node *node = result->nodes;
      if (node) {
        argv[2] = mrb_ary_new_capa(mrb, 1);
        do {
          mrb_ary_push(mrb, argv[2], mrb_cares_get_ai(mrb, mrb_cares_args, node));
        } while ((node = node->ai_next));
      }
    } else {
      argv[3] = mrb_cares_response_error(mrb, status);
    }
    mrb_yield_argv(mrb, mrb_cares_args->block, NELEMS(argv), argv);

    mrb->jmp = prev_jmp;
  }
  MRB_CATCH(&c_jmp)
  {
    mrb->jmp = prev_jmp;
  }
  MRB_END_EXC(&c_jmp);

  ares_freeaddrinfo(result);
  mrb_iv_remove(mrb, mrb_cares_args->mrb_cares_ctx->cares, mrb_cares_args->obj_id);
}

static void
mrb_ares_getnameinfo_callback(void *arg, int status, int timeouts, char *node, char *service)
{
  struct mrb_cares_args *mrb_cares_args = (struct mrb_cares_args *) arg;
  if (ARES_EDESTRUCTION == status)
    return;

  mrb_state *mrb = mrb_cares_args->mrb_cares_ctx->mrb;
  struct mrb_jmpbuf* prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;

  MRB_TRY(&c_jmp)
  {
    mrb->jmp = &c_jmp;
    mrb_value argv[4] = {mrb_nil_value()};
    argv[0] = mrb_int_value(mrb, timeouts);
    if (likely(ARES_SUCCESS == status)) {
      if (node) {
        argv[1] = mrb_str_new_cstr(mrb, node);
      }
      if (service) {
        argv[2] = mrb_str_new_cstr(mrb, service);
      }
    } else {
      argv[3] = mrb_cares_response_error(mrb, status);
    }
    mrb_yield_argv(mrb, mrb_cares_args->block, NELEMS(argv), argv);

    mrb->jmp = prev_jmp;
  }
  MRB_CATCH(&c_jmp)
  {
    mrb->jmp = prev_jmp;
  }
  MRB_END_EXC(&c_jmp);

  mrb_iv_remove(mrb, mrb_cares_args->mrb_cares_ctx->cares, mrb_cares_args->obj_id);
}

static void
mrb_cares_parse_hostent(mrb_state *mrb, mrb_value argv[3], struct hostent *host)
{
  argv[1] = mrb_hash_new_capa(mrb, 3);
  mrb_hash_set(mrb, argv[1], mrb_symbol_value(mrb_intern_lit(mrb, "name")), mrb_str_new_cstr(mrb, host->h_name));
  char **aliases = host->h_aliases;
  mrb_value aliases_ary = mrb_ary_new(mrb);
  while (*aliases) {
    mrb_ary_push(mrb, aliases_ary, mrb_str_new_cstr(mrb, *aliases));
    aliases++;
  }
  mrb_hash_set(mrb, argv[1], mrb_symbol_value(mrb_intern_lit(mrb, "aliases")), aliases_ary);
  char **addrs = host->h_addr_list;
  char addr[INET6_ADDRSTRLEN];
  mrb_value addrs_ary = mrb_ary_new(mrb);
  while (*addrs) {
    ares_inet_ntop(host->h_addrtype, *addrs, addr, sizeof(addr));
    mrb_ary_push(mrb, addrs_ary, mrb_str_new_cstr(mrb, addr));
    addrs++;
  }
  mrb_hash_set(mrb, argv[1], mrb_symbol_value(mrb_intern_lit(mrb, "addr_list")), addrs_ary);
}

static void
mrb_ares_parse_ns_reply(mrb_state *mrb, mrb_value argv[3], unsigned char *abuf, int alen)
{
  struct hostent *host = NULL;
  int status = ares_parse_ns_reply(abuf, alen, &host);
  if (ARES_SUCCESS == status) {
    mrb_cares_parse_hostent(mrb, argv, host);
  } else {
    argv[2] = mrb_cares_response_error(mrb, status);
  }
  ares_free_hostent(host);
}

static void
mrb_ares_parse_mx_reply(mrb_state *mrb, mrb_value argv[3], unsigned char *abuf, int alen)
{
  struct ares_mx_reply* reply = NULL;
  int status = ares_parse_mx_reply(abuf, alen, &reply);
  if (ARES_SUCCESS == status) {
    argv[1] = mrb_ary_new_capa(mrb, 1);
    struct ares_mx_reply* reply_i = reply;
    while (reply_i) {
      mrb_value r = mrb_hash_new_capa(mrb, 2);
      mrb_hash_set(mrb, r, mrb_symbol_value(mrb_intern_lit(mrb, "host")), mrb_str_new_cstr(mrb, reply_i->host));
      mrb_hash_set(mrb, r, mrb_symbol_value(mrb_intern_lit(mrb, "priority")), mrb_fixnum_value(reply_i->priority));
      mrb_ary_push(mrb, argv[1], r);
      reply_i = reply_i->next;
    }
  } else {
    argv[2] = mrb_cares_response_error(mrb, status);
  }
  ares_free_data(reply);
}

static void
mrb_ares_parse_srv_reply(mrb_state *mrb, mrb_value argv[3], unsigned char *abuf, int alen)
{
  struct ares_srv_reply* reply = NULL;
  int status = ares_parse_srv_reply(abuf, alen, &reply);
  if (ARES_SUCCESS == status) {
    argv[1] = mrb_ary_new_capa(mrb, 1);
    struct ares_srv_reply * reply_i = reply;
    while (reply_i) {
      mrb_value pwph = mrb_hash_new_capa(mrb, 4);
      mrb_hash_set(mrb, pwph, mrb_symbol_value(mrb_intern_lit(mrb, "priority")), mrb_fixnum_value(reply_i->priority));
      mrb_hash_set(mrb, pwph, mrb_symbol_value(mrb_intern_lit(mrb, "weight")), mrb_fixnum_value(reply_i->weight));
      mrb_hash_set(mrb, pwph, mrb_symbol_value(mrb_intern_lit(mrb, "port")), mrb_fixnum_value(reply_i->port));
      mrb_hash_set(mrb, pwph, mrb_symbol_value(mrb_intern_lit(mrb, "host")), mrb_str_new_cstr(mrb, reply_i->host));
      mrb_ary_push(mrb, argv[1], pwph);
      reply_i = reply_i->next;
    }
  } else {
    argv[2] = mrb_cares_response_error(mrb, status);
  }
  ares_free_data(reply);  
}

static void
mrb_ares_search_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen)
{
  struct mrb_cares_args *mrb_cares_args = (struct mrb_cares_args *) arg;
  if (ARES_EDESTRUCTION == status)
    return;

  mrb_state *mrb = mrb_cares_args->mrb_cares_ctx->mrb;
  mrb_value argv[3] = {mrb_nil_value()};
  argv[0] = mrb_int_value(mrb, timeouts);
  if (likely(ARES_SUCCESS == status)) {
    switch(mrb_cares_args->type) {
      case ARES_REC_TYPE_NS: {
        mrb_ares_parse_ns_reply(mrb, argv, abuf, alen);
      } break;
      case ARES_REC_TYPE_MX: {
        mrb_ares_parse_mx_reply(mrb, argv, abuf, alen);
      } break;
      case ARES_REC_TYPE_SRV: {
        mrb_ares_parse_srv_reply(mrb, argv, abuf, alen);
      } break;
      default: {
        argv[2] = mrb_exc_new_str(mrb, E_NOTIMP_ERROR, mrb_integer_to_str(mrb, mrb_int_value(mrb, mrb_cares_args->type), 10));
      }
    }
  } else {
    argv[2] = mrb_cares_response_error(mrb, status);
  }
  mrb_yield_argv(mrb, mrb_cares_args->block, NELEMS(argv), argv);

  mrb_iv_remove(mrb, mrb_cares_args->mrb_cares_ctx->cares, mrb_cares_args->obj_id);
}

static mrb_value
mrb_ares_init_options(mrb_state *mrb, mrb_value self)
{
  mrb_value options_val, block = mrb_nil_value();
  mrb_get_args(mrb, "o&", &options_val, &block);
  struct mrb_cares_options *mrb_cares_options = mrb_data_get_ptr(mrb, options_val, &mrb_cares_options_type);
  if (unlikely(mrb_nil_p(block))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if (unlikely(MRB_TT_PROC != mrb_type(block))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "options"), options_val);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "block"),   block);

  struct mrb_cares_ctx *mrb_cares_ctx = mrb_realloc(mrb, DATA_PTR(self), sizeof(*mrb_cares_ctx));
  mrb_data_init(self, mrb_cares_ctx, &mrb_cares_ctx_type);
  mrb_cares_ctx->mrb = mrb;
  mrb_cares_ctx->addrinfo_class = mrb_class_get(mrb, "Addrinfo");
  mrb_cares_ctx->cares_args_class = mrb_class_get_under(mrb, mrb_obj_class(mrb, self), "_Args");
  mrb_cares_ctx->cares = self;
  mrb_cares_ctx->block = block;
  mrb_cares_ctx->channel = NULL;
  mrb_cares_ctx->destruction = FALSE;

  mrb_cares_options->options.sock_state_cb = mrb_ares_state_callback;
  mrb_cares_options->options.sock_state_cb_data = mrb_cares_ctx;
  mrb_cares_options->optmask |= ARES_OPT_SOCK_STATE_CB;

  int rc = ares_init_options(&mrb_cares_ctx->channel, &mrb_cares_options->options, mrb_cares_options->optmask);
  if (unlikely(rc != ARES_SUCCESS))
    mrb_cares_usage_error(mrb, "ares_init_options", rc);

  return self;
}

static mrb_value
mrb_cares_make_args_struct(mrb_state *mrb,
mrb_value self, struct mrb_cares_ctx *mrb_cares_ctx,
mrb_value block,
struct mrb_cares_args **mrb_cares_args)
{
  struct RData *args_data;
  Data_Make_Struct(mrb,
  mrb_cares_ctx->cares_args_class, struct mrb_cares_args,
  &mrb_cares_args_type, *mrb_cares_args, args_data);
  (*mrb_cares_args)->mrb_cares_ctx = mrb_cares_ctx;
  (*mrb_cares_args)->block = block;
  mrb_value args = mrb_obj_value(args_data);
  (*mrb_cares_args)->obj_id = mrb_intern_str(mrb, mrb_integer_to_str(mrb, mrb_int_value(mrb, mrb_obj_id(args)), 36));
  mrb_iv_set(mrb, args, mrb_intern_lit(mrb, "cares"), self);
  mrb_iv_set(mrb, args, mrb_intern_lit(mrb, "block"), block);

  return args;
}

static mrb_value
mrb_ares_getaddrinfo(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = DATA_PTR(self);
  const char *name = NULL, *service;
  mrb_value service_val;
  mrb_int flags = 0, family = AF_UNSPEC, socktype = 0, protocol = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "z!o|iiii&", &name, &service_val, &flags, &family, &socktype, &protocol, &block);

  switch(mrb_type(service_val)) {
    case MRB_TT_FALSE: {
      service = NULL;
    } break;
    case MRB_TT_INTEGER: {
      service_val = mrb_integer_to_str(mrb, service_val, 10);
      flags |= ARES_AI_NUMERICSERV;
    }
    case MRB_TT_STRING: {
      service = mrb_string_value_cstr(mrb, &service_val);
    } break;
    default:
      mrb_raise(mrb, E_TYPE_ERROR, "wrong service type, can be nil, Integer or String");
  }

  struct ares_addrinfo_hints hints = {
    .ai_flags = (int) flags,
    .ai_family = (int) family,
    .ai_socktype = (int) socktype,
    .ai_protocol = (int) protocol
  };

  if (unlikely(mrb_nil_p(block))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if (unlikely(MRB_TT_PROC != mrb_type(block))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }

  struct mrb_cares_args *mrb_cares_args;
  mrb_value addrinfo = mrb_cares_make_args_struct(mrb, self, mrb_cares_ctx, block, &mrb_cares_args);

  ares_getaddrinfo(mrb_cares_ctx->channel,
    name, service,
    &hints,
    mrb_ares_getaddrinfo_callback, mrb_cares_args);

  mrb_iv_set(mrb, self, mrb_cares_args->obj_id, addrinfo); 

  return self;
}

static mrb_value
mrb_ares_getnameinfo(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = DATA_PTR(self);
  struct sockaddr_storage ss = {0};
  ares_socklen_t salen;
  mrb_int af;
  const char *ip_address = NULL;
  mrb_int port = 0, flags = 0;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "i|z!ii&", &af, &ip_address, &port, &flags, &block);

  ss.ss_family = (sa_family_t) af;
  switch (ss.ss_family) {
    case AF_INET: {
      struct sockaddr_in *sa_in = (struct sockaddr_in *) &ss;
      salen = sizeof(struct sockaddr_in);
      if (ip_address)
        ares_inet_pton(ss.ss_family, ip_address, &(sa_in->sin_addr));
      if (port)
        sa_in->sin_port = htons((uint16_t) port);
    } break;
    case AF_INET6: {
      struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *) &ss;
      salen = sizeof(struct sockaddr_in6);
      if (ip_address)
        ares_inet_pton(ss.ss_family, ip_address, &(sa_in6->sin6_addr));
      if (port)
        sa_in6->sin6_port = htons((uint16_t) port);
    } break;
    default: {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "af must be AF_INET or AF_INET6");
    }
  }
  if (ip_address)
    flags |= ARES_NI_LOOKUPHOST;
  if (port)
    flags |= ARES_NI_LOOKUPSERVICE;

  if (unlikely(mrb_nil_p(block))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if (unlikely(MRB_TT_PROC != mrb_type(block))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }

  struct mrb_cares_args *mrb_cares_args;
  mrb_value addrinfo = mrb_cares_make_args_struct(mrb, self, mrb_cares_ctx, block, &mrb_cares_args);

  ares_getnameinfo(mrb_cares_ctx->channel,
    (const struct sockaddr *) &ss, salen,
    flags,
    mrb_ares_getnameinfo_callback, mrb_cares_args);

  mrb_iv_set(mrb, self, mrb_cares_args->obj_id, addrinfo); 

  return self;
}

static mrb_value
mrb_ares_search(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = DATA_PTR(self);
  const char *name;
  mrb_sym type_sym;
  mrb_value block = mrb_nil_value();
  mrb_get_args(mrb, "zn&", &name, &type_sym, &block);
  mrb_int type = mrb_integer(mrb_hash_get(mrb, mrb_const_get(mrb, mrb_obj_value(mrb_obj_class(mrb, self)), mrb_intern_lit(mrb, "RecType")), mrb_symbol_value(type_sym)));
  if (type) {
    struct mrb_cares_args *mrb_cares_args;
    mrb_value search = mrb_cares_make_args_struct(mrb, self, mrb_cares_ctx, block, &mrb_cares_args);
    mrb_cares_args->type = type;

    ares_search(mrb_cares_ctx->channel, name, ARES_CLASS_IN, (int) type, mrb_ares_search_callback, mrb_cares_args);
    mrb_iv_set(mrb, self, mrb_cares_args->obj_id, search); 
  } else {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "wrong type");
  }

  return self;
}

static mrb_value
mrb_ares_timeout(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = DATA_PTR(self);
  mrb_float tmt = 0.0;
  mrb_get_args(mrb, "|f", &tmt); 
  struct timeval tv = {0};
  if (tmt > 0.0) {
    tmt += 0.5e-9; // we are adding this so maxtv can't become negative.
    struct timeval maxtv = {
      .tv_sec = tmt,
      .tv_usec = (tmt - (mrb_int)(tmt)) * USEC_PER_SEC
    };
    ares_timeout(mrb_cares_ctx->channel, &maxtv, &tv);
  } else {
    ares_timeout(mrb_cares_ctx->channel, NULL, &tv);
  }

  return mrb_float_value(mrb, (mrb_float) tv.tv_sec + ((mrb_float) tv.tv_usec / (mrb_float) USEC_PER_SEC));
}

static mrb_value
mrb_ares_process_fd(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = DATA_PTR(self);

  mrb_value read_fd;
  mrb_value write_fd;
  mrb_get_args(mrb, "oo", &read_fd, &write_fd);

  ares_process_fd(mrb_cares_ctx->channel,
  (ares_socket_t) mrb_integer(mrb_convert_type(mrb, read_fd,  MRB_TT_INTEGER, "Integer", "fileno")),
  (ares_socket_t) mrb_integer(mrb_convert_type(mrb, write_fd, MRB_TT_INTEGER, "Integer", "fileno")));

  return self;
}

static mrb_value
mrb_ares_set_servers_ports_csv(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = DATA_PTR(self);
  const char *servers;
  mrb_get_args(mrb, "z", &servers);

  int rc = ares_set_servers_ports_csv(mrb_cares_ctx->channel, servers);
  if (unlikely(rc != ARES_SUCCESS)) {
    mrb_cares_usage_error(mrb, "ares_set_servers_ports_csv", rc);
  }
  return self;
}

static mrb_value
mrb_ares_set_local_ip4(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = DATA_PTR(self);
  const char *local_ip4;
  mrb_get_args(mrb, "z", &local_ip4);
  struct in_addr addr;
  if (ares_inet_pton(AF_INET, local_ip4, &(addr.s_addr)) != 0) {
    mrb_sys_fail(mrb, "ares_inet_pton");
  }

  ares_set_local_ip4(mrb_cares_ctx->channel, addr.s_addr);

  return self;
}

static mrb_value
mrb_ares_set_local_ip6(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = DATA_PTR(self);
  const char *local_ip6;
  mrb_get_args(mrb, "z", &local_ip6);

  unsigned char buf[sizeof(struct in6_addr)];
  if (ares_inet_pton(AF_INET6, local_ip6, buf) != 0) {
    mrb_sys_fail(mrb, "ares_inet_pton");
  }

  ares_set_local_ip6(mrb_cares_ctx->channel, buf);

  return self;
}

static mrb_value
mrb_ares_options_new(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = mrb_realloc(mrb, DATA_PTR(self), sizeof(*mrb_cares_options));
  memset(mrb_cares_options, '\0', sizeof(*mrb_cares_options));
  mrb_data_init(self, mrb_cares_options, &mrb_cares_options_type);

  return self;
}

#ifdef ARES_OPT_FLAGS
static mrb_value
mrb_ares_options_flags_get(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.flags);
}

static mrb_value
mrb_ares_options_flags_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_int flags;
  mrb_get_args(mrb, "i", &flags);
  mrb_cares_options->options.flags = (int) flags;
  if (flags) {
    mrb_cares_options->optmask |= ARES_OPT_FLAGS;
  } else {
    mrb_cares_options->optmask &= ~ARES_OPT_FLAGS;
  }

  return self;
}
#endif
#ifdef ARES_OPT_TIMEOUTMS
static mrb_value
mrb_ares_options_timeout_get(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.timeout);
}

static mrb_value
mrb_ares_options_timeout_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_int timeout;
  mrb_get_args(mrb, "i", &timeout);
  mrb_cares_options->options.timeout = (int) timeout;
  if (timeout) {
    mrb_cares_options->optmask |= ARES_OPT_TIMEOUTMS;
  } else {
    mrb_cares_options->optmask &= ~ARES_OPT_TIMEOUTMS;
  }

  return self;
}
#endif
#ifdef ARES_OPT_TRIES
static mrb_value
mrb_ares_options_tries_get(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.tries);
}

static mrb_value
mrb_ares_options_tries_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_int tries;
  mrb_get_args(mrb, "i", &tries);
  mrb_cares_options->options.tries = (int) tries;
  if (tries) {
    mrb_cares_options->optmask |= ARES_OPT_TRIES;
  } else {
    mrb_cares_options->optmask &= ~ARES_OPT_TRIES;
  }

  return self;
}
#endif
#ifdef ARES_OPT_NDOTS
static mrb_value
mrb_ares_options_ndots_get(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.ndots);
}

static mrb_value
mrb_ares_options_ndots_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_int ndots;
  mrb_get_args(mrb, "i", &ndots);
  mrb_cares_options->options.ndots = (int) ndots;
  if (ndots) {
    mrb_cares_options->optmask |= ARES_OPT_NDOTS;
  } else {
    mrb_cares_options->optmask &= ~ARES_OPT_NDOTS;
  }

  return self;
}
#endif
#ifdef ARES_OPT_DOMAINS
static mrb_value
mrb_ares_options_domains_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);

  mrb_value *argv;
  mrb_int argc;
  mrb_get_args(mrb, "*", &argv, &argc);
  mrb_cares_options->options.domains = mrb_realloc(mrb, mrb_cares_options->options.domains, argc * sizeof(mrb_value));
  mrb_cares_options->options.ndomains = (int) argc;

  if (argc) {
    for (int i = 0; i < argc; i++) {
      mrb_cares_options->options.domains[i] = mrb_string_value_cstr(mrb, &argv[i]);
    }
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@domains"), mrb_ary_new_from_values(mrb, argc, argv));
    mrb_cares_options->optmask |= ARES_OPT_DOMAINS;
  } else {
    mrb_cares_options->options.domains = NULL;
    mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "@domains"));
    mrb_cares_options->optmask &= ~ARES_OPT_DOMAINS;
  }
  return self;
}
#endif
#ifdef ARES_OPT_EDNSPSZ
static mrb_value
mrb_ares_options_ednspsz_get(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.ednspsz);
}

static mrb_value
mrb_ares_options_ednspsz_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_int ednspsz;
  mrb_get_args(mrb, "i", &ednspsz);
  mrb_cares_options->options.ednspsz = (int) ednspsz;
  if (ednspsz) {
    mrb_cares_options->optmask |= ARES_OPT_EDNSPSZ;
  } else {
    mrb_cares_options->optmask &= ~ARES_OPT_EDNSPSZ;
  }

  return self;
}
#endif
#ifdef ARES_OPT_RESOLVCONF
static mrb_value
mrb_ares_options_resolvconf_path_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_value resolvconf_path;
  mrb_get_args(mrb, "S!", &resolvconf_path);
  if (mrb_string_p(resolvconf_path)) {
    mrb_cares_options->options.resolvconf_path = mrb_string_value_cstr(mrb, &resolvconf_path);
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@resolvconf_path"), resolvconf_path);
    mrb_cares_options->optmask |= ARES_OPT_RESOLVCONF;
  } else {
    mrb_cares_options->options.resolvconf_path = NULL;
    mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "@resolvconf_path"));
    mrb_cares_options->optmask &= ~ARES_OPT_RESOLVCONF;
  }

  return self;
}
#endif
#ifdef ARES_OPT_HOSTS_FILE
static mrb_value
mrb_ares_options_hosts_path_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_value hosts_path;
  mrb_get_args(mrb, "S!", &hosts_path);
  if (mrb_string_p(hosts_path)) {
    mrb_cares_options->options.hosts_path = mrb_string_value_cstr(mrb, &hosts_path);
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@hosts_path"), hosts_path);
    mrb_cares_options->optmask |= ARES_OPT_HOSTS_FILE;
  } else {
    mrb_cares_options->options.hosts_path = NULL;
    mrb_iv_remove(mrb, self, mrb_intern_lit(mrb, "@hosts_path"));
    mrb_cares_options->optmask &= ~ARES_OPT_HOSTS_FILE;
  }

  return self;
}
#endif
#ifdef ARES_OPT_UDP_MAX_QUERIES
static mrb_value
mrb_ares_options_udp_max_queries_get(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.udp_max_queries);
}

static mrb_value
mrb_ares_options_udp_max_queries_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_int udp_max_queries;
  mrb_get_args(mrb, "i", &udp_max_queries);
  mrb_cares_options->options.udp_max_queries = (int) udp_max_queries;
  if (udp_max_queries) {
    mrb_cares_options->optmask |= ARES_OPT_UDP_MAX_QUERIES;
  } else {
    mrb_cares_options->optmask &= ~ARES_OPT_UDP_MAX_QUERIES;
  }

  return self;
}
#endif
#ifdef ARES_OPT_MAXTIMEOUTMS
static mrb_value
mrb_ares_options_maxtimeout_get(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.maxtimeout);
}

static mrb_value
mrb_ares_options_maxtimeout_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_int maxtimeout;
  mrb_get_args(mrb, "i", &maxtimeout);
  mrb_cares_options->options.maxtimeout = (int) maxtimeout;
  if (maxtimeout) {
    mrb_cares_options->optmask |= ARES_OPT_MAXTIMEOUTMS;
  } else {
    mrb_cares_options->optmask &= ~ARES_OPT_MAXTIMEOUTMS;
  }

  return self;
}
#endif
#ifdef ARES_OPT_QUERY_CACHE
static mrb_value
mrb_ares_options_qcache_max_ttl_get(mrb_state *mrb, mrb_value self)
{
  return mrb_int_value(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.qcache_max_ttl);
}

static mrb_value
mrb_ares_options_qcache_max_ttl_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_int qcache_max_ttl;
  mrb_get_args(mrb, "i", &qcache_max_ttl);
  mrb_cares_options->options.qcache_max_ttl = (unsigned int) qcache_max_ttl;
  if (qcache_max_ttl) {
    mrb_cares_options->optmask |= ARES_OPT_QUERY_CACHE;
  } else {
    mrb_cares_options->optmask &= ~ARES_OPT_QUERY_CACHE;
  }

  return self;
}
#endif
void
mrb_mruby_c_ares_gem_init(mrb_state* mrb)
{
#ifdef _WIN32
  WSADATA wsaData;
  int result;
  result = WSAStartup(MAKEWORD(2,2), &wsaData);
  if (result != NO_ERROR)
    mrb_raise(mrb, E_RUNTIME_ERROR, "WSAStartup failed");
#endif
  int rc = ares_library_init(ARES_LIB_INIT_ALL);
  if (unlikely(rc != 0))
    mrb_cares_usage_error(mrb, "ares_library_init", rc);

  struct RClass *mrb_ares_class, *mrb_ares_options_class, *mrb_ares_error_class, *mrb_ares_args_class;

  mrb_ares_class = mrb_define_class(mrb, "Ares", mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_class, MRB_TT_CDATA);
  mrb_define_const (mrb, mrb_ares_class, "VERSION",           mrb_str_new_lit_frozen(mrb, ARES_VERSION_STR));
  mrb_define_method(mrb, mrb_ares_class, "initialize",        mrb_ares_init_options,          MRB_ARGS_REQ(1)|MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mrb_ares_class, "getaddrinfo",       mrb_ares_getaddrinfo,           MRB_ARGS_REQ(3)|MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mrb_ares_class, "getnameinfo",       mrb_ares_getnameinfo,           MRB_ARGS_ARG(1, 1)|MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mrb_ares_class, "search",            mrb_ares_search,                MRB_ARGS_REQ(3)|MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mrb_ares_class, "timeout",           mrb_ares_timeout,               MRB_ARGS_OPT(1));
  mrb_define_method(mrb, mrb_ares_class, "process_fd",        mrb_ares_process_fd,            MRB_ARGS_REQ(2));
  mrb_define_method(mrb, mrb_ares_class, "servers_ports_csv=",mrb_ares_set_servers_ports_csv, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_class, "local_ip4=",        mrb_ares_set_local_ip4,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_class, "local_ip6=",        mrb_ares_set_local_ip6,         MRB_ARGS_REQ(1));
  mrb_ares_options_class = mrb_define_class_under(mrb, mrb_ares_class, "Options", mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_options_class, MRB_TT_CDATA);
  mrb_value available_options = mrb_ary_new(mrb);
  mrb_define_const (mrb, mrb_ares_options_class, "AVAILABLE_OPTIONS", available_options);
  mrb_define_method(mrb, mrb_ares_options_class, "initialize",      mrb_ares_options_new,                 MRB_ARGS_NONE());
#ifdef ARES_OPT_FLAGS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "flags")));
  mrb_define_method(mrb, mrb_ares_options_class, "flags",           mrb_ares_options_flags_get,           MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "flags=",          mrb_ares_options_flags_set,           MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_TIMEOUTMS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "timeout")));
  mrb_define_method(mrb, mrb_ares_options_class, "timeout",         mrb_ares_options_timeout_get,         MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "timeout=",        mrb_ares_options_timeout_set,         MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_TRIES
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "tries")));
  mrb_define_method(mrb, mrb_ares_options_class, "tries",           mrb_ares_options_tries_get,           MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "tries=",          mrb_ares_options_tries_set,           MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_NDOTS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "ndots")));
  mrb_define_method(mrb, mrb_ares_options_class, "ndots",           mrb_ares_options_ndots_get,           MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "ndots=",          mrb_ares_options_ndots_set,           MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_DOMAINS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "domains_set")));
  mrb_define_method(mrb, mrb_ares_options_class, "domains_set",     mrb_ares_options_domains_set,         MRB_ARGS_ANY());
#endif
#ifdef ARES_OPT_EDNSPSZ
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "ednspsz")));
  mrb_define_method(mrb, mrb_ares_options_class, "ednspsz",         mrb_ares_options_ednspsz_get,         MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "ednspsz=",        mrb_ares_options_ednspsz_set,         MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_RESOLVCONF
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "resolvconf_path")));
  mrb_define_method(mrb, mrb_ares_options_class, "resolvconf_path=",mrb_ares_options_resolvconf_path_set, MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_HOSTS_FILE
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "hosts_path")));
  mrb_define_method(mrb, mrb_ares_options_class, "hosts_path=",     mrb_ares_options_hosts_path_set,      MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_UDP_MAX_QUERIES
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "udp_max_queries")));
  mrb_define_method(mrb, mrb_ares_options_class, "udp_max_queries", mrb_ares_options_udp_max_queries_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "udp_max_queries=",mrb_ares_options_udp_max_queries_set, MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_MAXTIMEOUTMS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "maxtimeout")));
  mrb_define_method(mrb, mrb_ares_options_class, "maxtimeout",      mrb_ares_options_maxtimeout_get,      MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "maxtimeout=",     mrb_ares_options_maxtimeout_set,      MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_QUERY_CACHE
  mrb_ary_push(mrb, available_options, mrb_symbol_value(mrb_intern_lit(mrb, "qcache_max_ttl")));
  mrb_define_method(mrb, mrb_ares_options_class, "qcache_max_ttl",  mrb_ares_options_qcache_max_ttl_get,  MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "qcache_max_ttl=", mrb_ares_options_qcache_max_ttl_set,  MRB_ARGS_REQ(1));
#endif
  mrb_ares_args_class = mrb_define_class_under(mrb, mrb_ares_class, "_Args", mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_args_class, MRB_TT_CDATA);
  mrb_ares_error_class = mrb_define_class_under(mrb, mrb_ares_class, "Error", E_RUNTIME_ERROR);
  
#define mrb_cares_define_const(ARES_CONST_NAME, ARES_CONST) \
  do { \
    mrb_define_const(mrb, mrb_ares_class, ARES_CONST_NAME, mrb_int_value(mrb, ARES_CONST)); \
  } while(0)
#include "cares_const.cstub"

  mrb_value errno_to_class = mrb_hash_new(mrb);
  mrb_define_const(mrb, mrb_ares_class, "_Errno2Class", errno_to_class);
#define mrb_cares_define_ares_status(ARES_ENUM_NAME, ARES_ENUM) \
  do { \
    struct RClass *enum_err_class = mrb_define_class_under(mrb, mrb_ares_class, ARES_ENUM_NAME, mrb_ares_error_class); \
    mrb_hash_set(mrb, errno_to_class, mrb_int_value(mrb, ARES_ENUM), mrb_obj_value(enum_err_class)); \
  } while(0)

  mrb_value rec_type = mrb_hash_new(mrb);
  mrb_define_const(mrb, mrb_ares_class, "RecType", rec_type);
#define mrb_cares_define_ares_dns_rec_type(ARES_ENUM_NAME, ARES_ENUM) \
  do { \
    mrb_hash_set(mrb, rec_type, mrb_symbol_value(mrb_intern_cstr(mrb, ARES_ENUM_NAME)), mrb_int_value(mrb, ARES_ENUM)); \
  } while(0)

  mrb_value ares_dns_class = mrb_hash_new(mrb);
  mrb_define_const(mrb, mrb_ares_class, "DnsClass", ares_dns_class);
#define mrb_cares_define_ares_dns_class(ARES_ENUM_NAME, ARES_ENUM) \
  do { \
    mrb_hash_set(mrb, ares_dns_class, mrb_symbol_value(mrb_intern_cstr(mrb, ARES_ENUM_NAME)), mrb_int_value(mrb, ARES_ENUM)); \
  } while(0)

#include "cares_enums.cstub"
  mrb_obj_freeze(mrb, available_options);
  mrb_obj_freeze(mrb, errno_to_class);
  mrb_obj_freeze(mrb, rec_type);
  mrb_obj_freeze(mrb, ares_dns_class);
}

void
mrb_mruby_c_ares_gem_final(mrb_state* mrb)
{
  ares_library_cleanup();
#ifdef _WIN32
  WSACleanup();
#endif
}