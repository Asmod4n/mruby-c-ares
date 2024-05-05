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
  if (likely(status != ARES_EDESTRUCTION)) {
    struct mrb_cares_addrinfo *mrb_cares_addrinfo = (struct mrb_cares_addrinfo *) arg;
    mrb_value argv[3] = {mrb_nil_value()};
    if (likely(status == ARES_SUCCESS)) {
      struct ares_addrinfo_cname *cname = result->cnames;
      struct ares_addrinfo_node *node = result->nodes;
      if (cname) {
        argv[0] = mrb_ary_new_capa(mrb_cares_addrinfo->mrb_cares_ctx->mrb, 1);
        do {
          mrb_ary_push(mrb_cares_addrinfo->mrb_cares_ctx->mrb, argv[0], mrb_str_new_cstr(mrb_cares_addrinfo->mrb_cares_ctx->mrb, cname->name));
        } while ((cname = cname->next));
      }
      if (node) {
        argv[1] = mrb_ary_new_capa(mrb_cares_addrinfo->mrb_cares_ctx->mrb, 1);
        do {
          mrb_ary_push(mrb_cares_addrinfo->mrb_cares_ctx->mrb, argv[1], mrb_cares_get_ai(mrb_cares_addrinfo, node));
        } while ((node = node->ai_next));
      }
    } else {
      argv[2] = mrb_cares_response_error(mrb_cares_addrinfo->mrb_cares_ctx->mrb, status);
    }
    mrb_yield_argv(mrb_cares_addrinfo->mrb_cares_ctx->mrb, mrb_cares_addrinfo->block, NELEMS(argv), argv);
    mrb_iv_remove(mrb_cares_addrinfo->mrb_cares_ctx->mrb, mrb_cares_addrinfo->cares, mrb_cares_addrinfo->obj_id);
  }

  ares_freeaddrinfo(result);
}

static void
mrb_ares_state_callback(void *data, ares_socket_t socket_fd, int readable, int writable)
{
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) data;
  mrb_state *mrb = mrb_cares_ctx->mrb;
  int arena_index = mrb_gc_arena_save(mrb);

  mrb_value argv[] = {mrb_int_value(mrb, socket_fd), mrb_bool_value(readable), mrb_bool_value(writable)};
  mrb_yield(mrb, mrb_cares_ctx->block, mrb_obj_new(mrb, mrb_cares_ctx->cares_socket_class, NELEMS(argv), argv));
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
  mrb_cares_ctx->block = block;
  mrb_cares_ctx->channel = NULL;
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
  (*mrb_cares_addrinfo)->cares = self;
  (*mrb_cares_addrinfo)->mrb_cares_ctx = mrb_cares_ctx;
  (*mrb_cares_addrinfo)->family = ss->ss_family;
  (*mrb_cares_addrinfo)->block = block;
  mrb_value addrinfo = mrb_obj_value(addrinfo_data);
  mrb_iv_set(mrb, addrinfo, mrb_intern_lit(mrb, "cares"), self);
  mrb_iv_set(mrb, addrinfo, mrb_intern_lit(mrb, "block"), block);
  (*mrb_cares_addrinfo)->obj_id = mrb_intern_str(mrb, mrb_integer_to_str(mrb, mrb_int_value(mrb, mrb_obj_id(addrinfo)), 36));

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
  mrb_int flags;
  mrb_get_args(mrb, "i", &flags);
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_cares_options->options.flags = (int) flags;
  mrb_cares_options->optmask |= ARES_OPT_FLAGS;

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
  mrb_int timeout;
  mrb_get_args(mrb, "i", &timeout);
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_cares_options->options.timeout = (int) timeout;
  mrb_cares_options->optmask |= ARES_OPT_TIMEOUTMS;

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
  mrb_int tries;
  mrb_get_args(mrb, "i", &tries);
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_cares_options->options.tries = (int) tries;
  mrb_cares_options->optmask |= ARES_OPT_TRIES;

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
  mrb_int ndots;
  mrb_get_args(mrb, "i", &ndots);
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_cares_options->options.ndots = (int) ndots;
  mrb_cares_options->optmask |= ARES_OPT_NDOTS;

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
  mrb_int maxtimeout;
  mrb_get_args(mrb, "i", &maxtimeout);
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_cares_options->options.maxtimeout = (int) maxtimeout;
  mrb_cares_options->optmask |= ARES_OPT_MAXTIMEOUTMS;

  return self;
}

static mrb_value
mrb_ares_options_udp_port_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct mrb_cares_options *)DATA_PTR(self))->options.udp_port);
}

static mrb_value
mrb_ares_options_udp_port_set(mrb_state *mrb, mrb_value self)
{
  mrb_int udp_port;
  mrb_get_args(mrb, "i", &udp_port);
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_cares_options->options.udp_port = (unsigned short) udp_port;
  mrb_cares_options->optmask |= ARES_OPT_UDP_PORT;

  return self;
}

static mrb_value
mrb_ares_options_tcp_port_get(mrb_state *mrb, mrb_value self)
{
  return mrb_fixnum_value(((struct mrb_cares_options *)DATA_PTR(self))->options.tcp_port);
}

static mrb_value
mrb_ares_options_tcp_port_set(mrb_state *mrb, mrb_value self)
{
  mrb_int tcp_port;
  mrb_get_args(mrb, "i", &tcp_port);
  struct mrb_cares_options *mrb_cares_options = DATA_PTR(self);
  mrb_cares_options->options.tcp_port = (unsigned short) tcp_port;
  mrb_cares_options->optmask |= ARES_OPT_TCP_PORT;

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
  mrb_define_method(mrb,  mrb_ares_class, "initialize",   mrb_ares_init_options,MRB_ARGS_REQ(1)|MRB_ARGS_BLOCK());
  mrb_define_method(mrb,  mrb_ares_class, "getaddrinfo",  mrb_ares_getaddrinfo, MRB_ARGS_REQ(3)|MRB_ARGS_BLOCK());
  mrb_define_method(mrb,  mrb_ares_class, "timeout",      mrb_ares_timeout,     MRB_ARGS_OPT(1));
  mrb_define_method(mrb,  mrb_ares_class, "process_fd",   mrb_ares_process_fd,  MRB_ARGS_REQ(2));
  mrb_ares_options_class = mrb_define_class_under(mrb, mrb_ares_class, "Options", mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_options_class, MRB_TT_CDATA);
  mrb_define_method(mrb, mrb_ares_options_class, "initialize",  mrb_ares_options_new,             MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "flags",       mrb_ares_options_flags_get,       MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "flags=",      mrb_ares_options_flags_set,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "timeout",     mrb_ares_options_timeout_get,     MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "timeout=",    mrb_ares_options_timeout_set,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "tries",       mrb_ares_options_tries_get,       MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "tries=",      mrb_ares_options_tries_set,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "ndots",       mrb_ares_options_ndots_get,       MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "ndots=",      mrb_ares_options_ndots_set,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "maxtimeout",  mrb_ares_options_maxtimeout_get,  MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "maxtimeout=", mrb_ares_options_maxtimeout_set,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "udp_port",    mrb_ares_options_udp_port_get,    MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "udp_port=",   mrb_ares_options_udp_port_set,    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, mrb_ares_options_class, "tcp_port",    mrb_ares_options_tcp_port_get,    MRB_ARGS_NONE());
  mrb_define_method(mrb, mrb_ares_options_class, "tcp_port=",   mrb_ares_options_tcp_port_set,    MRB_ARGS_REQ(1));
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