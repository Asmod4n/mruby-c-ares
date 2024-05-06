#include "mrb_c_ares.h"

static mrb_value
mrb_cares_get_ai(struct mrb_cares_addrinfo *mrb_cares_addrinfo, struct ares_addrinfo_node *node)
{
  mrb_value storage;
  if (mrb_cares_addrinfo->family == AF_INET6 && node->ai_family == AF_INET) {
    struct sockaddr_in *sa_in     = (struct sockaddr_in *) node->ai_addr;
    struct sockaddr_in6 sa_in6    = {0};
    sa_in6.sin6_family            = AF_INET6;
    sa_in6.sin6_port              = sa_in->sin_port;
    sa_in6.sin6_addr.s6_addr[10]  = 0xff;
    sa_in6.sin6_addr.s6_addr[11]  = 0xff;
    memcpy(sa_in6.sin6_addr.s6_addr + 12, &sa_in->sin_addr, sizeof(sa_in->sin_addr));
    storage = mrb_str_new(mrb_cares_addrinfo->mrb_cares_ctx->mrb, (const char *) &sa_in6, sizeof(sa_in6));
  } else {
    storage = mrb_str_new(mrb_cares_addrinfo->mrb_cares_ctx->mrb, (const char *) node->ai_addr, node->ai_addrlen);
  }

  mrb_value argv[] = {
    storage,
    mrb_fixnum_value(node->ai_family),
    mrb_fixnum_value(node->ai_socktype),
    mrb_fixnum_value(node->ai_protocol)
  };

  return mrb_obj_new(mrb_cares_addrinfo->mrb_cares_ctx->mrb, mrb_cares_addrinfo->mrb_cares_ctx->addrinfo_class, NELEMS(argv), argv);
}

static void 
mrb_ares_getaddrinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *result)
{
  struct mrb_cares_addrinfo *mrb_cares_addrinfo = (struct mrb_cares_addrinfo *) arg;
  if (status == ARES_EDESTRUCTION)
    return;
  if (status == ARES_ECANCELLED)
    return;

  mrb_state *mrb = mrb_cares_addrinfo->mrb_cares_ctx->mrb;
  struct mrb_jmpbuf* prev_jmp = mrb->jmp;
  struct mrb_jmpbuf c_jmp;

  MRB_TRY(&c_jmp)
  {
    mrb->jmp = &c_jmp;
    mrb_value argv[3] = {mrb_nil_value()};
    if (likely(status == ARES_SUCCESS)) {
      struct ares_addrinfo_cname *cname = result->cnames;
      struct ares_addrinfo_node *node = result->nodes;
      if (cname) {
        argv[0] = mrb_ary_new_capa(mrb, 1);
        do {
          mrb_ary_push(mrb, argv[0], mrb_str_new_cstr(mrb, cname->name));
        } while ((cname = cname->next));
      }
      if (node) {
        argv[1] = mrb_ary_new_capa(mrb, 1);
        do {
          mrb_ary_push(mrb, argv[1], mrb_cares_get_ai(mrb_cares_addrinfo, node));
        } while ((node = node->ai_next));
      }
    } else {
      argv[2] = mrb_cares_response_error(mrb, status);
    }
    mrb_yield_argv(mrb, mrb_cares_addrinfo->block, NELEMS(argv), argv);

    mrb->jmp = prev_jmp;
  }
  MRB_CATCH(&c_jmp)
  {
    mrb->jmp = prev_jmp;
  }
  MRB_END_EXC(&c_jmp);

  mrb_iv_remove(mrb, mrb_cares_addrinfo->mrb_cares_ctx->cares, mrb_cares_addrinfo->obj_id);
  ares_freeaddrinfo(result);
}

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
    mrb_yield(mrb, mrb_cares_ctx->block, mrb_obj_new(mrb, mrb_cares_ctx->cares_socket_class, NELEMS(argv), argv));
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
  mrb_cares_ctx->cares_addrinfo_class = mrb_class_get_under(mrb, mrb_obj_class(mrb, self), "_Addrinfo");
  mrb_cares_ctx->cares_socket_class = mrb_class_get_under(mrb, mrb_obj_class(mrb, self), "Socket");
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
mrb_cares_make_addrinfo_struct(mrb_state *mrb,
mrb_value self, struct mrb_cares_ctx *mrb_cares_ctx,
mrb_value block, struct sockaddr_storage *ss,
struct mrb_cares_addrinfo **mrb_cares_addrinfo)
{
  struct RData *addrinfo_data;
  Data_Make_Struct(mrb,
  mrb_cares_ctx->cares_addrinfo_class, struct mrb_cares_addrinfo,
  &mrb_cares_addrinfo_type, *mrb_cares_addrinfo, addrinfo_data);
  (*mrb_cares_addrinfo)->mrb_cares_ctx = mrb_cares_ctx;
  (*mrb_cares_addrinfo)->family = ss->ss_family;
  (*mrb_cares_addrinfo)->block = block;
  mrb_value addrinfo = mrb_obj_value(addrinfo_data);
  (*mrb_cares_addrinfo)->obj_id = mrb_intern_str(mrb, mrb_integer_to_str(mrb, mrb_int_value(mrb, mrb_obj_id(addrinfo)), 36));
  mrb_iv_set(mrb, addrinfo, mrb_intern_lit(mrb, "cares"), self);
  mrb_iv_set(mrb, addrinfo, mrb_intern_lit(mrb, "block"), block);

  return addrinfo;
}

static mrb_value
mrb_ares_getaddrinfo(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = DATA_PTR(self);
  mrb_value sock, name, service, block = mrb_nil_value();
  mrb_get_args(mrb, "oSS&", &sock, &name, &service, &block);
  ares_socket_t socket = (ares_socket_t) mrb_integer(mrb_convert_type(mrb, sock, MRB_TT_INTEGER, "Integer", "fileno"));
  if (unlikely(mrb_nil_p(block))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if (unlikely(MRB_TT_PROC != mrb_type(block))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }
  struct sockaddr_storage ss;
  socklen_t optlen = sizeof(ss);
  if (unlikely(getsockname(socket, (struct sockaddr *) &ss, &optlen) == -1)) {
    mrb_sys_fail(mrb, "getsockname");
  }
  int socktype;
  optlen = sizeof(socktype);
  if (unlikely(getsockopt(socket, SOL_SOCKET, SO_TYPE, &socktype, &optlen) == -1)) {
    mrb_sys_fail(mrb, "getsockopt");
  }
  struct ares_addrinfo_hints hints = {
    .ai_family = ss.ss_family,
    .ai_socktype = socktype
  };

  struct mrb_cares_addrinfo *mrb_cares_addrinfo;
  mrb_value addrinfo = mrb_cares_make_addrinfo_struct(mrb, self, mrb_cares_ctx, block, &ss, &mrb_cares_addrinfo);

  switch (ss.ss_family) {
    case AF_INET: {
      ares_getaddrinfo(mrb_cares_ctx->channel,
      mrb_string_value_cstr(mrb, &name), mrb_string_value_cstr(mrb, &service),
      &hints, mrb_ares_getaddrinfo_callback, mrb_cares_addrinfo);
    } break;
    case AF_INET6: {
      int v6_only = 0;
      optlen = sizeof(v6_only);
      getsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, &optlen);
      if (!v6_only) {
        hints.ai_family = AF_UNSPEC;
      }
      ares_getaddrinfo(mrb_cares_ctx->channel,
      mrb_string_value_cstr(mrb, &name), mrb_string_value_cstr(mrb, &service),
      &hints, mrb_ares_getaddrinfo_callback, mrb_cares_addrinfo);
    } break;
    default: {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "Not a IPv4 or IPv6 socket");
    }
  }

  mrb_iv_set(mrb, self, mrb_cares_addrinfo->obj_id, addrinfo); 

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

static mrb_value
mrb_ares_options_flags_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct mrb_cares_options *)DATA_PTR(self))->options.flags);
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

static mrb_value
mrb_ares_options_timeout_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct mrb_cares_options *)DATA_PTR(self))->options.timeout);
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

static mrb_value
mrb_ares_options_tries_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct mrb_cares_options *)DATA_PTR(self))->options.tries);
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

static mrb_value
mrb_ares_options_ndots_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct mrb_cares_options *)DATA_PTR(self))->options.ndots);
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

static mrb_value
mrb_ares_options_ednspsz_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct mrb_cares_options *)DATA_PTR(self))->options.ednspsz);
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

static mrb_value
mrb_ares_options_udp_max_queries_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct mrb_cares_options *)DATA_PTR(self))->options.udp_max_queries);
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

static mrb_value
mrb_ares_options_maxtimeout_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct mrb_cares_options *)DATA_PTR(self))->options.maxtimeout);
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

  struct RClass *mrb_ares_class, *mrb_ares_options_class, *mrb_ares_error_class, *mrb_ares_addrinfo_class;

  mrb_ares_class = mrb_define_class(mrb, "Ares", mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_class, MRB_TT_CDATA);
  mrb_define_method(mrb, mrb_ares_class, "initialize",        mrb_ares_init_options,          MRB_ARGS_REQ(1)|MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mrb_ares_class, "getaddrinfo",       mrb_ares_getaddrinfo,           MRB_ARGS_REQ(3)|MRB_ARGS_BLOCK());
  mrb_define_method(mrb, mrb_ares_class, "timeout",           mrb_ares_timeout,               MRB_ARGS_OPT(1));
  mrb_define_method(mrb, mrb_ares_class, "process_fd",        mrb_ares_process_fd,            MRB_ARGS_REQ(2));
  mrb_define_method(mrb, mrb_ares_class, "servers_ports_csv=",mrb_ares_set_servers_ports_csv, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_class, "local_ip4=",        mrb_ares_set_local_ip4,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_class, "local_ip6=",        mrb_ares_set_local_ip6,         MRB_ARGS_REQ(1));
  mrb_ares_options_class = mrb_define_class_under(mrb, mrb_ares_class, "Options", mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_options_class, MRB_TT_CDATA);
  mrb_define_method(mrb, mrb_ares_options_class, "initialize",      mrb_ares_options_new,                 MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "flags",           mrb_ares_options_flags_get,           MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "flags=",          mrb_ares_options_flags_set,           MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "timeout",         mrb_ares_options_timeout_get,         MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "timeout=",        mrb_ares_options_timeout_set,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "tries",           mrb_ares_options_tries_get,           MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "tries=",          mrb_ares_options_tries_set,           MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "ndots",           mrb_ares_options_ndots_get,           MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "ndots=",          mrb_ares_options_ndots_set,           MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "domains_set",     mrb_ares_options_domains_set,         MRB_ARGS_ANY());
  mrb_define_method(mrb, mrb_ares_options_class, "ednspsz",         mrb_ares_options_ednspsz_get,         MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "ednspsz=",        mrb_ares_options_ednspsz_set,         MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "resolvconf_path=",mrb_ares_options_resolvconf_path_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "hosts_path=",     mrb_ares_options_hosts_path_set,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "udp_max_queries", mrb_ares_options_udp_max_queries_get, MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "udp_max_queries=",mrb_ares_options_udp_max_queries_set, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "maxtimeout",      mrb_ares_options_maxtimeout_get,      MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "maxtimeout=",     mrb_ares_options_maxtimeout_set,      MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "qcache_max_ttl",  mrb_ares_options_qcache_max_ttl_get,  MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "qcache_max_ttl=", mrb_ares_options_qcache_max_ttl_set,  MRB_ARGS_REQ(1));

  mrb_ares_addrinfo_class = mrb_define_class_under(mrb, mrb_ares_class, "_Addrinfo", mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_addrinfo_class, MRB_TT_CDATA);
  mrb_ares_error_class = mrb_define_class_under(mrb, mrb_ares_class, "Error", E_RUNTIME_ERROR);
  
#define mrb_cares_define_const(ARES_CONST_NAME, ARES_CONST) \
  do { \
    mrb_define_const(mrb, mrb_ares_class, ARES_CONST_NAME, mrb_int_value(mrb, ARES_CONST)); \
  } while(0)
#include "cares_const.cstub"

  mrb_value errno_to_class = mrb_hash_new(mrb);
  mrb_define_const(mrb, mrb_ares_class, "_Errno2Class", errno_to_class);
#define mrb_cares_define_error(ARES_ENUM_NAME, ARES_ENUM) \
  do { \
    struct RClass *enum_err_class = mrb_define_class_under(mrb, mrb_ares_class, ARES_ENUM_NAME, mrb_ares_error_class); \
    mrb_hash_set(mrb, errno_to_class, mrb_int_value(mrb, ARES_ENUM), mrb_obj_value(enum_err_class)); \
  } while(0)

#include "cares_enums.cstub"
}

void
mrb_mruby_c_ares_gem_final(mrb_state* mrb)
{
  ares_library_cleanup();
#ifdef _WIN32
  WSACleanup();
#endif
}