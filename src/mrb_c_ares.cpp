#include "mruby/common.h"
#define _DEFAULT_SOURCE
#include <mruby.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <winerror.h>
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/param.h>
  #include <sys/un.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <sys/time.h>
  #include <sys/select.h>
#endif

#include <mruby/value.h>
#if MRB_INT_BIT < 64
#error "need 64 bit mruby"
#endif
#include <mruby/variable.h>
#include <mruby/error.h>
#include <mruby/data.h>
#include <mruby/class.h>
#include <mruby/string.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/numeric.h>
#include <mruby/num_helpers.hpp>
#include <mruby/presym.h>
#include <functional>

#include <ares.h>
#if !((ARES_VERSION_MAJOR == 1 && ARES_VERSION_MINOR >= 16) || ARES_VERSION_MAJOR > 1)
#error "mruby-c-ares needs at least c-ares Version 1.16.0"
#endif
#include <ares_dns_record.h>

#if (__GNUC__ >= 3) || (__INTEL_COMPILER >= 800) || defined(__clang__)
# define likely(x) __builtin_expect(!!(x), 1)
# define unlikely(x) __builtin_expect(!!(x), 0)
#else
# define likely(x) (x)
# define unlikely(x) (x)
#endif

#ifndef USEC_PER_SEC
#define USEC_PER_SEC 1000000UL
#endif

#define NELEMS(argv) (sizeof(argv) / sizeof(argv[0]))

struct mrb_cares_ctx {
  mrb_state *mrb;
  mrb_value cares;
  mrb_value block;
  ares_channel channel;
  mrb_bool destruction;
};

struct mrb_cares_args {
  struct mrb_cares_ctx *mrb_cares_ctx;
  mrb_value block;
  mrb_int obj_id;
  ares_dns_rec_type_t type;
};

struct mrb_cares_options {
  struct ares_options options;
  int optmask;
};

static void
mrb_cares_ctx_free(mrb_state *mrb, void *p)
{
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) p;
  mrb_cares_ctx->destruction = TRUE;
  ares_destroy(mrb_cares_ctx->channel);
  mrb_free(mrb, p);
}

static void
mrb_cares_options_free(mrb_state *mrb, void *p)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) p;
#ifdef ARES_OPT_DOMAINS
  mrb_free(mrb, mrb_cares_options->options.domains);
#endif
  mrb_free(mrb, p);
}

static const struct mrb_data_type mrb_cares_ctx_type = {
  "$i_mrb_mrb_cares_ctx_t", mrb_cares_ctx_free
};

static const struct mrb_data_type mrb_cares_args_type = {
  "$i_mrb_cares_args_t", mrb_free
};

static const struct mrb_data_type mrb_cares_options_type = {
  "$i_mrb_cares_options_t", mrb_cares_options_free
};

static void
mrb_cares_usage_error(mrb_state *mrb, const char *funcname, int rc)
{
  mrb_value errno_to_class = mrb_const_get(mrb, mrb_obj_value(mrb_class_get_id(mrb, MRB_SYM(Ares))), MRB_SYM(_Errno2Class));
  mrb_value errno_class = mrb_hash_get(mrb, errno_to_class, mrb_convert_number(mrb, rc));
  if (mrb_nil_p(errno_class)) {
    mrb_raisef(mrb, mrb_class_get_under_id(mrb, mrb_class_get_id(mrb, MRB_SYM(Ares)), MRB_SYM(Error)), "%s: %s", funcname, ares_strerror(rc));
  } else {
    mrb_raisef(mrb, mrb_class_ptr(errno_class), "%s: %s", funcname, ares_strerror(rc));
  }
}

static mrb_value
mrb_cares_response_error(mrb_state *mrb, int status)
{
  mrb_value errno_to_class = mrb_const_get(mrb, mrb_obj_value(mrb_class_get_id(mrb, MRB_SYM(Ares))), MRB_SYM(_Errno2Class));
  mrb_value errno_class = mrb_hash_get(mrb, errno_to_class, mrb_convert_number(mrb, status));
  if (mrb_nil_p(errno_class)) {
    return mrb_exc_new_str(mrb, mrb_class_get_under_id(mrb, mrb_class_get_id(mrb, MRB_SYM(Ares)), MRB_SYM(Error)), mrb_str_new_cstr(mrb, ares_strerror(status)));
  } else {
    return mrb_exc_new_str(mrb, mrb_class_ptr(errno_class), mrb_str_new_cstr(mrb, ares_strerror(status)));
  }
}

static void
mrb_ares_sock_state_cb(void *data, ares_socket_t socket_fd, int readable, int writable)
{
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) data;
  if (mrb_cares_ctx->destruction)
    return;
  mrb_state *mrb = mrb_cares_ctx->mrb;
  int idx = mrb_gc_arena_save(mrb);

  mrb_value argv[] = {mrb_convert_number(mrb, socket_fd), mrb_bool_value(readable), mrb_bool_value(writable)};
  mrb_yield_argv(mrb, mrb_cares_ctx->block, NELEMS(argv), argv);

  mrb_gc_arena_restore(mrb, idx);
}

static mrb_value
mrb_cares_get_ai(mrb_state *mrb, struct mrb_cares_args *mrb_cares_args, struct ares_addrinfo_node *node)
{
  mrb_value argv[] = {
    mrb_str_new(mrb, (const char *) node->ai_addr, node->ai_addrlen),
    mrb_convert_number(mrb, node->ai_family),
    mrb_convert_number(mrb, node->ai_socktype),
    mrb_convert_number(mrb, node->ai_protocol)
  };

  return mrb_obj_new(mrb, mrb_class_get_id(mrb, MRB_SYM(Addrinfo)), NELEMS(argv), argv);
}

static void
mrb_ares_getaddrinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *result)
{
  struct mrb_cares_args *mrb_cares_args = (struct mrb_cares_args *) arg;
  if (ARES_EDESTRUCTION == status)
    return;

  mrb_state *mrb = mrb_cares_args->mrb_cares_ctx->mrb;
  int idx = mrb_gc_arena_save(mrb);

  auto cleanup = [&] {
    ares_freeaddrinfo(result);
    mrb_iv_remove(mrb, mrb_cares_args->mrb_cares_ctx->cares, mrb_cares_args->obj_id);
  };
  struct Guard {
      std::function<void()> fn;
      ~Guard() { fn(); }
  } guard{cleanup};

  mrb_value argv[4] = {mrb_nil_value()};
  argv[0] = mrb_convert_number(mrb, timeouts);
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
  mrb_gc_arena_restore(mrb, idx);
}

static void
mrb_ares_getnameinfo_callback(void *arg, int status, int timeouts, char *node, char *service)
{
  struct mrb_cares_args *mrb_cares_args = (struct mrb_cares_args *) arg;
  if (ARES_EDESTRUCTION == status)
    return;

  mrb_state *mrb = mrb_cares_args->mrb_cares_ctx->mrb;
  int idx = mrb_gc_arena_save(mrb);
  mrb_value argv[4] = {mrb_nil_value()};
  argv[0] = mrb_convert_number(mrb, timeouts);
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
  mrb_iv_remove(mrb, mrb_cares_args->mrb_cares_ctx->cares, mrb_cares_args->obj_id);
  mrb_yield_argv(mrb, mrb_cares_args->block, NELEMS(argv), argv);
  mrb_gc_arena_restore(mrb, idx);
}

static mrb_value
mrb_ares_init_options(mrb_state *mrb, mrb_value self)
{
  mrb_value options_val, block = mrb_nil_value();
  mrb_get_args(mrb, "o&", &options_val, &block);
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, options_val, &mrb_cares_options_type);
  if (unlikely(mrb_nil_p(block))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if (unlikely(MRB_TT_PROC != mrb_type(block))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }
  mrb_iv_set(mrb, self, MRB_SYM(options), options_val);
  mrb_iv_set(mrb, self, MRB_SYM(block),   block);

  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*mrb_cares_ctx));
  mrb_data_init(self, mrb_cares_ctx, &mrb_cares_ctx_type);
  mrb_cares_ctx->mrb = mrb;
  mrb_cares_ctx->cares = self;
  mrb_cares_ctx->block = block;
  mrb_cares_ctx->channel = NULL;
  mrb_cares_ctx->destruction = FALSE;

  mrb_cares_options->options.sock_state_cb = mrb_ares_sock_state_cb;
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
  mrb_class_get_under_id(mrb, mrb_obj_class(mrb, self), MRB_SYM(_Args)), struct mrb_cares_args,
  &mrb_cares_args_type, *mrb_cares_args, args_data);
  (*mrb_cares_args)->mrb_cares_ctx = mrb_cares_ctx;
  (*mrb_cares_args)->block = block;
  mrb_value args = mrb_obj_value(args_data);
  (*mrb_cares_args)->obj_id = mrb_obj_id(args);
  mrb_iv_set(mrb, args, MRB_SYM(cares), self);
  mrb_iv_set(mrb, args, MRB_SYM(block), block);

  return args;
}

static mrb_value
mrb_ares_getaddrinfo(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) mrb_data_get_ptr(mrb, self, &mrb_cares_ctx_type);
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

  if (unlikely(mrb_nil_p(block))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if (unlikely(MRB_TT_PROC != mrb_type(block))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }

  struct ares_addrinfo_hints hints = {
    .ai_flags = (int) flags,
    .ai_family = (int) family,
    .ai_socktype = (int) socktype,
    .ai_protocol = (int) protocol
  };

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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) mrb_data_get_ptr(mrb, self, &mrb_cares_ctx_type);
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
  mrb_value nameinfo = mrb_cares_make_args_struct(mrb, self, mrb_cares_ctx, block, &mrb_cares_args);

  ares_getnameinfo(mrb_cares_ctx->channel,
    (const struct sockaddr *) &ss, salen,
    flags,
    mrb_ares_getnameinfo_callback, mrb_cares_args);

  mrb_iv_set(mrb, self, mrb_cares_args->obj_id, nameinfo);

  return self;
}

static mrb_value
mrb_cares_lookup_symbol(mrb_state *mrb,
                        struct mrb_cares_args *args,
                        mrb_int value,
                        mrb_bool is_type)
{
  mrb_value inv = mrb_const_get(
    mrb,
    mrb_obj_value(mrb_obj_class(mrb, args->mrb_cares_ctx->cares)),
    is_type ? MRB_SYM(RecTypeInverse) : MRB_SYM(DnsClassInverse)
  );

  mrb_value key = mrb_convert_number(mrb, value);
  mrb_value sym = mrb_hash_get(mrb, inv, key);

  if (mrb_nil_p(sym)) {
    return mrb_symbol_value(MRB_SYM(UNKNOWN));
  }
  return sym;
}

/* ============================================================
 *  Lookup: RR key → presym (via Ares::RRFieldMap)
 * ============================================================ */

static mrb_sym
mrb_cares_lookup_rr_field(mrb_state *mrb, ares_dns_rr_key_t key)
{
  mrb_value mod = mrb_obj_value(mrb_class_get_id(mrb, MRB_SYM(Ares)));
  mrb_value map = mrb_const_get(mrb, mod, MRB_SYM(RRFieldMap));

  mrb_value v = mrb_hash_get(mrb, map, mrb_convert_number(mrb, key));
  if (mrb_nil_p(v)) return 0;
  return mrb_symbol(v);
}

static mrb_value
mrb_cares_decode_ipv4_list(mrb_state *mrb, const unsigned char *buf, size_t len)
{
  mrb_value ary = mrb_ary_new(mrb);
  char out[INET_ADDRSTRLEN];

  if (len % 4 != 0) return ary;

  for (size_t i = 0; i < len; i += 4) {
    if (!inet_ntop(AF_INET, buf + i, out, sizeof(out))) continue;
    mrb_ary_push(mrb, ary, mrb_str_new_cstr(mrb, out));
  }

  return ary;
}

static mrb_value
mrb_cares_decode_ipv6_list(mrb_state *mrb, const unsigned char *buf, size_t len)
{
  mrb_value ary = mrb_ary_new(mrb);
  char out[INET6_ADDRSTRLEN];

  if (len % 16 != 0) return ary;

  for (size_t i = 0; i < len; i += 16) {
    if (!inet_ntop(AF_INET6, buf + i, out, sizeof(out))) continue;
    mrb_ary_push(mrb, ary, mrb_str_new_cstr(mrb, out));
  }

  return ary;
}

/* ============================================================
 *  OPT/SVCB/HTTPS Parameter Parser (using ares_dns_rr_get_opt)
 * ============================================================ */

static mrb_value
mrb_ares_parse_opt_params(mrb_state *mrb,
                          const ares_dns_rr_t *rr,
                          ares_dns_rr_key_t key)
{
  mrb_value mod = mrb_obj_value(mrb_class_get_id(mrb, MRB_SYM(Ares)));
  mrb_value map = mrb_const_get(mrb, mod, MRB_SYM(RROptParamMap));

  size_t count = ares_dns_rr_get_opt_cnt(rr, key);
  mrb_value params = mrb_hash_new_capa(mrb, count);

  for (size_t idx = 0; idx < count; idx++) {
    const unsigned char *val = NULL;
    size_t val_len = 0;

    /* c-ares API: returns the option code */
    unsigned short opt_code =
      ares_dns_rr_get_opt(rr, key, idx, &val, &val_len);

    if (opt_code == 65535) {
      /* error or malformed */
      continue;
    }

    /* Lookup Ruby key (symbol) */
    mrb_value key_val =
      mrb_hash_get(mrb, map, mrb_convert_number(mrb, opt_code));

    mrb_value ruby_key =
      mrb_nil_p(key_val)
        ? mrb_convert_number(mrb, opt_code)
        : key_val;

    mrb_value ruby_val;

    switch (opt_code) {

      case ARES_SVCB_PARAM_IPV4HINT:
        ruby_val = mrb_cares_decode_ipv4_list(mrb, val, val_len);
        break;

      case ARES_SVCB_PARAM_IPV6HINT:
        ruby_val = mrb_cares_decode_ipv6_list(mrb, val, val_len);
        break;

      default:
        /* raw binary string */
        ruby_val = mrb_str_new(mrb, (const char*)val, (mrb_int)val_len);
        break;
    }

    mrb_hash_set(mrb, params, ruby_key, ruby_val);
  }

  return params;
}


/* ============================================================
 *  Generic RR Parser
 * ============================================================ */

static void
mrb_ares_parse_rr_generic(mrb_state *mrb,
                          mrb_value hash,
                          const ares_dns_rr_t *rr)
{
  ares_dns_rec_type_t type = ares_dns_rr_get_type(rr);

  size_t cnt = 0;
  const ares_dns_rr_key_t *keys = ares_dns_rr_get_keys(type, &cnt);
  if (!keys) return;

  for (size_t i = 0; i < cnt; i++) {
    ares_dns_rr_key_t key = keys[i];
    mrb_sym sym = mrb_cares_lookup_rr_field(mrb, key);
    if (!sym) continue;

    ares_dns_datatype_t dt = ares_dns_rr_key_datatype(key);

    switch (dt) {

      /* -------------------- IPv4 -------------------- */
      case ARES_DATATYPE_INADDR: {
        const struct in_addr *a4 = ares_dns_rr_get_addr(rr, key);
        if (!a4) break;
        char buf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, a4, buf, sizeof(buf))) break;
        mrb_hash_set(mrb, hash, mrb_symbol_value(sym),
                     mrb_str_new_cstr(mrb, buf));
        break;
      }

      /* -------------------- IPv6 -------------------- */
      case ARES_DATATYPE_INADDR6: {
        const struct ares_in6_addr *a6 = ares_dns_rr_get_addr6(rr, key);
        if (!a6) break;
        char buf[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, a6, buf, sizeof(buf))) break;
        mrb_hash_set(mrb, hash, mrb_symbol_value(sym),
                     mrb_str_new_cstr(mrb, buf));
        break;
      }

      /* -------------------- Integers -------------------- */
      case ARES_DATATYPE_U8:
        mrb_hash_set(mrb, hash, mrb_symbol_value(sym),
                     mrb_convert_number(mrb, ares_dns_rr_get_u8(rr, key)));
        break;

      case ARES_DATATYPE_U16:
        mrb_hash_set(mrb, hash, mrb_symbol_value(sym),
                     mrb_convert_number(mrb, ares_dns_rr_get_u16(rr, key)));
        break;

      case ARES_DATATYPE_U32:
        mrb_hash_set(mrb, hash, mrb_symbol_value(sym),
                     mrb_convert_number(mrb, ares_dns_rr_get_u32(rr, key)));
        break;

      /* -------------------- Strings -------------------- */
      case ARES_DATATYPE_NAME:
      case ARES_DATATYPE_STR: {
        const char *s = ares_dns_rr_get_str(rr, key);
        if (!s) break;
        mrb_hash_set(mrb, hash, mrb_symbol_value(sym),
                     mrb_str_new_cstr(mrb, s));
        break;
      }

      /* -------------------- Binary (single) -------------------- */
      case ARES_DATATYPE_BIN:
      case ARES_DATATYPE_BINP: {
        size_t len = 0;
        const unsigned char *bin = ares_dns_rr_get_bin(rr, key, &len);
        if (!bin) break;
        mrb_hash_set(mrb, hash,
          mrb_symbol_value(sym),
          mrb_str_new(mrb, (const char *)bin, (mrb_int)len));
        break;
      }

      /* -------------------- Binary array (ABINP) -------------------- */
      case ARES_DATATYPE_ABINP: {
        size_t acnt = ares_dns_rr_get_abin_cnt(rr, key);
        mrb_value ary = mrb_ary_new_capa(mrb, acnt);

        for (size_t idx = 0; idx < acnt; idx++) {
          size_t len = 0;
          const unsigned char *bin =
            ares_dns_rr_get_abin(rr, key, idx, &len);

          if (!bin) continue;

          mrb_value val =
            mrb_str_new(mrb, (const char *)bin, (mrb_int)len);

          mrb_ary_push(mrb, ary, val);
        }

        mrb_hash_set(mrb, hash,
          mrb_symbol_value(sym),
          ary);
        break;
      }

      /* -------------------- OPT/SVCB/HTTPS -------------------- */
      case ARES_DATATYPE_OPT: {
        mrb_value params =
          mrb_ares_parse_opt_params(mrb, rr, key);

        mrb_hash_set(mrb, hash,
          mrb_symbol_value(sym),
          params);
        break;
      }
    }
  }
}

/* ============================================================
 *  Parse Answer + Authority + Additional
 * ============================================================ */

static void
mrb_ares_parse_dnsrec_list(mrb_state *mrb,
                           struct mrb_cares_args *args,
                           mrb_value argv[3],
                           const ares_dns_record_t *rec_root)
{
  mrb_value answers   = mrb_ary_new(mrb);
  mrb_value authority = mrb_ary_new(mrb);
  mrb_value additional= mrb_ary_new(mrb);

  struct {
    ares_dns_section_t sec;
    mrb_value          ary;
  } sections[3] = {
    { ARES_SECTION_ANSWER,     answers },
    { ARES_SECTION_AUTHORITY,  authority },
    { ARES_SECTION_ADDITIONAL, additional }
  };

  for (int s = 0; s < 3; s++) {
    size_t cnt = ares_dns_record_rr_cnt(rec_root, sections[s].sec);

    for (size_t i = 0; i < cnt; i++) {
      const ares_dns_rr_t *rr =
        ares_dns_record_rr_get_const(rec_root, sections[s].sec, i);
      if (!rr) continue;

      mrb_value hash = mrb_hash_new_capa(mrb, 8);

      const char           *name = ares_dns_rr_get_name(rr);
      ares_dns_rec_type_t   type = ares_dns_rr_get_type(rr);
      ares_dns_class_t      cls  = ares_dns_rr_get_class(rr);
      unsigned int          ttl  = ares_dns_rr_get_ttl(rr);

      if (name) {
        mrb_hash_set(mrb, hash,
          mrb_symbol_value(MRB_SYM(name)),
          mrb_str_new_cstr(mrb, name));
      }

      mrb_value type_sym = mrb_cares_lookup_symbol(mrb, args, type, TRUE);
      mrb_hash_set(mrb, hash, mrb_symbol_value(MRB_SYM(type)), type_sym);

      mrb_value class_sym =
        mrb_cares_lookup_symbol(mrb, args, cls, FALSE);

      mrb_hash_set(mrb, hash,
        mrb_symbol_value(MRB_SYM(class)),
        class_sym);


      mrb_hash_set(mrb, hash,
        mrb_symbol_value(MRB_SYM(ttl)),
        mrb_convert_number(mrb, ttl));

      mrb_ares_parse_rr_generic(mrb, hash, rr);

      mrb_ary_push(mrb, sections[s].ary, hash);
    }
  }

  argv[1] = answers;

  mrb_value extra = mrb_hash_new(mrb);
  mrb_hash_set(mrb, extra,
    mrb_symbol_value(MRB_SYM(authority)),  authority);
  mrb_hash_set(mrb, extra,
    mrb_symbol_value(MRB_SYM(additional)), additional);

  argv[2] = extra;
}


//-------------------------------------------------------------------------
// 2) Callback matching the 7-arg ares_query_dnsrec API
//-------------------------------------------------------------------------
static void
mrb_ares_query_dnsrec_cb(void                     *arg,
                         ares_status_t             status,
                         unsigned long             timeouts,
                         const ares_dns_record_t  *dnsrec)
{
  struct mrb_cares_args *args = (struct mrb_cares_args*)arg;
  if (status == ARES_EDESTRUCTION) {
    return;
  }

  mrb_state *mrb = args->mrb_cares_ctx->mrb;
  int idx = mrb_gc_arena_save(mrb);
  mrb_value argv[3] = {
    mrb_convert_number(mrb, timeouts),
    mrb_nil_value(),
    mrb_nil_value()
  };

  if (status == ARES_SUCCESS) {
    mrb_ares_parse_dnsrec_list(mrb, args, argv, dnsrec);
  } else {
    argv[2] = mrb_cares_response_error(mrb, status);
  }

  mrb_iv_remove(mrb,
    args->mrb_cares_ctx->cares,
    args->obj_id);

  mrb_yield_argv(mrb, args->block, NELEMS(argv), argv);
  mrb_gc_arena_restore(mrb, idx);
}

//-------------------------------------------------------------------------
// 3) Entry point: query(name, :TYPE) { |timeouts, results, error| … }
//-------------------------------------------------------------------------
static mrb_value
mrb_ares_query(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *ctx =
    (struct mrb_cares_ctx*) mrb_data_get_ptr(mrb, self, &mrb_cares_ctx_type);
  const char *name;
  mrb_sym    type_sym = 0;
  mrb_sym    class_sym = 0;
  mrb_value  block = mrb_nil_value();

  // name, type, class, block — class is optional
  mrb_get_args(mrb, "zn|n&", &name, &type_sym, &class_sym, &block);
  if (unlikely(mrb_nil_p(block))) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "no block given");
  }
  if (unlikely(MRB_TT_PROC != mrb_type(block))) {
    mrb_raise(mrb, E_TYPE_ERROR, "not a block");
  }
  // lookup type
  mrb_value rec_hash = mrb_const_get(mrb,
                        mrb_obj_value(mrb_obj_class(mrb, self)),
                        MRB_SYM(RecType));
  mrb_int type = mrb_integer(mrb_hash_get(mrb,
                        rec_hash,
                        mrb_symbol_value(type_sym)));
  if (type <= 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "wrong type");
  }

  // lookup class (default to IN if not provided)
  mrb_value class_hash = mrb_const_get(mrb,
                          mrb_obj_value(mrb_obj_class(mrb, self)),
                          MRB_SYM(DnsClass));
  mrb_int dnsclass = mrb_integer(mrb_hash_get(mrb,
                            class_hash,
                            mrb_symbol_value(class_sym ? class_sym : MRB_SYM(IN))));
  if (dnsclass <= 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "wrong class");
  }

  struct mrb_cares_args *args;
  mrb_value holder = mrb_cares_make_args_struct(
                       mrb, self, ctx, block, &args);
  args->type = (ares_dns_rec_type_t)type;

  unsigned short tmout = 0;
  ares_status_t st = ares_query_dnsrec(
    ctx->channel,
    name,
    (ares_dns_class_t)dnsclass,
    (ares_dns_rec_type_t)type,
    mrb_ares_query_dnsrec_cb,
    args,
    &tmout
  );
  if (st != ARES_SUCCESS) {
    mrb_raise(mrb, E_RUNTIME_ERROR, ares_strerror(st));
  }

  mrb_iv_set(mrb, self, args->obj_id, holder);
  return mrb_convert_number(mrb, tmout);
}


static mrb_value
mrb_ares_timeout(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) mrb_data_get_ptr(mrb, self, &mrb_cares_ctx_type);
  mrb_float tmt = 0.0;
  int argc = mrb_get_args(mrb, "|f", &tmt);
  struct timeval tv = {0};
  if (argc == 1) {
    tmt += 0.5e-7; // we are adding this so maxtv can't become negative.
    struct timeval maxtv = {
      .tv_sec = (__time_t) tmt,
      .tv_usec = (long) ((tmt - (mrb_int)(tmt)) * USEC_PER_SEC)
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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) mrb_data_get_ptr(mrb, self, &mrb_cares_ctx_type);

  mrb_value read_fd;
  mrb_value write_fd;
  mrb_get_args(mrb, "oo", &read_fd, &write_fd);

  ares_process_fd(mrb_cares_ctx->channel,
  (ares_socket_t) mrb_integer(mrb_type_convert(mrb, read_fd,  MRB_TT_INTEGER, MRB_SYM(fileno))),
  (ares_socket_t) mrb_integer(mrb_type_convert(mrb, write_fd, MRB_TT_INTEGER, MRB_SYM(fileno))));

  return self;
}

static mrb_value
mrb_ares_set_servers_ports_csv(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) mrb_data_get_ptr(mrb, self, &mrb_cares_ctx_type);
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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) mrb_data_get_ptr(mrb, self, &mrb_cares_ctx_type);
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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) mrb_data_get_ptr(mrb, self, &mrb_cares_ctx_type);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_realloc(mrb, DATA_PTR(self), sizeof(*mrb_cares_options));
  memset(mrb_cares_options, '\0', sizeof(*mrb_cares_options));
  mrb_data_init(self, mrb_cares_options, &mrb_cares_options_type);

  return self;
}

#ifdef ARES_OPT_FLAGS
static mrb_value
mrb_ares_options_flags_get(mrb_state *mrb, mrb_value self)
{
  return mrb_convert_number(mrb, ((struct mrb_cares_options *)mrb_data_get_ptr(mrb, self, &mrb_cares_options_type))->options.flags);
}

static mrb_value
mrb_ares_options_flags_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
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
  return mrb_convert_number(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.timeout);
}

static mrb_value
mrb_ares_options_timeout_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
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
  return mrb_convert_number(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.tries);
}

static mrb_value
mrb_ares_options_tries_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
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
  return mrb_convert_number(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.ndots);
}

static mrb_value
mrb_ares_options_ndots_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);

  mrb_value *argv;
  mrb_int argc;
  mrb_get_args(mrb, "*", &argv, &argc);
  mrb_cares_options->options.domains = (char **) mrb_realloc(mrb, mrb_cares_options->options.domains, argc * sizeof(char *));
  mrb_cares_options->options.ndomains = (int) argc;
  mrb_value domains = mrb_ary_new_capa(mrb, argc);
  if (argc) {
    for (int i = 0; i < argc; i++) {
      mrb_value dupped = mrb_str_dup(mrb, argv[i]);
      mrb_cares_options->options.domains[i] = (char *) mrb_string_value_cstr(mrb, &dupped);
      mrb_obj_freeze(mrb, dupped);
      mrb_ary_push(mrb, domains, dupped);
    }
    mrb_iv_set(mrb, self, MRB_IVSYM(domains), domains);
    mrb_obj_freeze(mrb, domains);
    mrb_cares_options->optmask |= ARES_OPT_DOMAINS;
  } else {
    mrb_free(mrb, mrb_cares_options->options.domains);
    mrb_cares_options->options.domains = NULL;
    mrb_iv_remove(mrb, self, MRB_IVSYM(domains));
    mrb_cares_options->optmask &= ~ARES_OPT_DOMAINS;
  }
  return self;
}
#endif
#ifdef ARES_OPT_EDNSPSZ
static mrb_value
mrb_ares_options_ednspsz_get(mrb_state *mrb, mrb_value self)
{
  return mrb_convert_number(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.ednspsz);
}

static mrb_value
mrb_ares_options_ednspsz_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
  mrb_value resolvconf_path;
  mrb_get_args(mrb, "S!", &resolvconf_path);
  if (mrb_string_p(resolvconf_path)) {
    mrb_value dupped = mrb_str_dup(mrb, resolvconf_path);
    mrb_cares_options->options.resolvconf_path = (char *) mrb_string_value_cstr(mrb, &dupped);
    mrb_iv_set(mrb, self, MRB_IVSYM(resolvconf_path), dupped);
    mrb_obj_freeze(mrb, dupped);
    mrb_cares_options->optmask |= ARES_OPT_RESOLVCONF;
  } else {
    mrb_cares_options->options.resolvconf_path = NULL;
    mrb_iv_remove(mrb, self, MRB_IVSYM(resolvconf_path));
    mrb_cares_options->optmask &= ~ARES_OPT_RESOLVCONF;
  }

  return self;
}
#endif
#ifdef ARES_OPT_HOSTS_FILE
static mrb_value
mrb_ares_options_hosts_path_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
  mrb_value hosts_path;
  mrb_get_args(mrb, "S!", &hosts_path);
  if (mrb_string_p(hosts_path)) {
    mrb_value dupped = mrb_str_dup(mrb, hosts_path);
    mrb_cares_options->options.hosts_path = (char *) mrb_string_value_cstr(mrb, &dupped);
    mrb_iv_set(mrb, self, MRB_IVSYM(hosts_path), dupped);
    mrb_obj_freeze(mrb, dupped);
    mrb_cares_options->optmask |= ARES_OPT_HOSTS_FILE;
  } else {
    mrb_cares_options->options.hosts_path = NULL;
    mrb_iv_remove(mrb, self, MRB_IVSYM(hosts_path));
    mrb_cares_options->optmask &= ~ARES_OPT_HOSTS_FILE;
  }

  return self;
}
#endif
#ifdef ARES_OPT_UDP_MAX_QUERIES
static mrb_value
mrb_ares_options_udp_max_queries_get(mrb_state *mrb, mrb_value self)
{
  return mrb_convert_number(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.udp_max_queries);
}

static mrb_value
mrb_ares_options_udp_max_queries_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
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
  return mrb_convert_number(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.maxtimeout);
}

static mrb_value
mrb_ares_options_maxtimeout_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
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
  return mrb_convert_number(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.qcache_max_ttl);
}

static mrb_value
mrb_ares_options_qcache_max_ttl_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) mrb_data_get_ptr(mrb, self, &mrb_cares_options_type);
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

static mrb_value
mrb_cares_build_inverse(mrb_state *mrb, mrb_value forward)
{
  mrb_int sz = mrb_hash_size(mrb, forward);
  mrb_value inv = mrb_hash_new_capa(mrb, sz);

  auto cb = +[](mrb_state *mrb, mrb_value key, mrb_value val, void *ud) -> int {
    mrb_value inv = *(mrb_value*)ud;
    mrb_hash_set(mrb, inv, val, key);
    return 0; // continue
  };

  mrb_hash_foreach(mrb, mrb_hash_ptr(forward), cb, &inv);
  return inv;
}


MRB_BEGIN_DECL
MRB_API void
mrb_cares_bootstrap(mrb_state *mrb)
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

  mrb_ares_class = mrb_define_class_id(mrb, MRB_SYM(Ares), mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_class, MRB_TT_CDATA);
  mrb_define_const_id (mrb, mrb_ares_class, MRB_SYM(VERSION),           mrb_str_new_lit_frozen(mrb, ARES_VERSION_STR));
  mrb_ares_args_class = mrb_define_class_under_id(mrb, mrb_ares_class, MRB_SYM(_Args), mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_args_class, MRB_TT_CDATA);
  mrb_ares_error_class = mrb_define_class_under_id(mrb, mrb_ares_class, MRB_SYM(Error), E_RUNTIME_ERROR);

#define mrb_cares_define_const(ARES_CONST_NAME, ARES_CONST) \
  do { \
    mrb_define_const_id(mrb, mrb_ares_class, ARES_CONST_NAME, mrb_convert_number(mrb, ARES_CONST)); \
  } while(0)
#include "cares_const.cstub"

  mrb_value errno_to_class = mrb_hash_new(mrb);
  mrb_define_const_id(mrb, mrb_ares_class, MRB_SYM(_Errno2Class), errno_to_class);

#define mrb_cares_define_ares_status(ARES_ENUM_NAME, ARES_ENUM) \
  do { \
    struct RClass *enum_err_class = mrb_define_class_under_id(mrb, mrb_ares_class, ARES_ENUM_NAME, mrb_ares_error_class); \
    mrb_hash_set(mrb, errno_to_class, mrb_convert_number(mrb, ARES_ENUM), mrb_obj_value(enum_err_class)); \
  } while(0)

  mrb_value rec_type = mrb_hash_new(mrb);
  mrb_define_const_id(mrb, mrb_ares_class, MRB_SYM(RecType), rec_type);
#define mrb_cares_define_ares_dns_rec_type(ARES_ENUM_NAME, ARES_ENUM) \
  do { \
    mrb_hash_set(mrb, rec_type, mrb_symbol_value(ARES_ENUM_NAME), mrb_convert_number(mrb, ARES_ENUM)); \
  } while(0)

  mrb_value ares_dns_class = mrb_hash_new(mrb);
  mrb_define_const_id(mrb, mrb_ares_class, MRB_SYM(DnsClass), ares_dns_class);
#define mrb_cares_define_ares_dns_class_type(ARES_ENUM_NAME, ARES_ENUM) \
  do { \
    mrb_hash_set(mrb, ares_dns_class, mrb_symbol_value(ARES_ENUM_NAME), mrb_convert_number(mrb, ARES_ENUM)); \
  } while(0)

#include "cares_enums.cstub"

  /* RRFieldMap */
  mrb_value rr_field_map = mrb_hash_new(mrb);
  mrb_define_const_id(mrb, mrb_ares_class, MRB_SYM(RRFieldMap), rr_field_map);

#include "cares_rr_fields.cstub"

  mrb_obj_freeze(mrb, rr_field_map);

  /* RROptParamMap */
  mrb_value rr_opt_param_map = mrb_hash_new(mrb);
  mrb_define_const_id(mrb, mrb_ares_class, MRB_SYM(RROptParamMap), rr_opt_param_map);

#include "cares_rr_opt_params.cstub"

  mrb_obj_freeze(mrb, rr_opt_param_map);

  mrb_value rec_type_inv  = mrb_cares_build_inverse(mrb, rec_type);
  mrb_value class_inv     = mrb_cares_build_inverse(mrb, ares_dns_class);

  mrb_define_const_id(mrb, mrb_ares_class, MRB_SYM(RecTypeInverse), rec_type_inv);
  mrb_define_const_id(mrb, mrb_ares_class, MRB_SYM(DnsClassInverse), class_inv);


  mrb_obj_freeze(mrb, errno_to_class);
  mrb_obj_freeze(mrb, rec_type);
  mrb_obj_freeze(mrb, ares_dns_class);
  mrb_obj_freeze(mrb, rec_type_inv);
  mrb_obj_freeze(mrb, class_inv);
}

MRB_API void
mrb_cares_register_ruby(mrb_state *mrb)
{
  struct RClass *mrb_ares_class, *mrb_ares_options_class;
  mrb_ares_class = mrb_class_get_id(mrb, MRB_SYM(Ares));
  mrb_define_method_id(mrb, mrb_ares_class, MRB_SYM(initialize),        mrb_ares_init_options,          MRB_ARGS_REQ(1)|MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, mrb_ares_class, MRB_SYM(getaddrinfo),       mrb_ares_getaddrinfo,           MRB_ARGS_REQ(3)|MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, mrb_ares_class, MRB_SYM(getnameinfo),       mrb_ares_getnameinfo,           MRB_ARGS_ARG(1, 1)|MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, mrb_ares_class, MRB_SYM(query),            mrb_ares_query,                MRB_ARGS_ARG(2, 1)|MRB_ARGS_BLOCK());
  mrb_define_alias_id (mrb, mrb_ares_class, MRB_SYM(search), MRB_SYM(query));
  mrb_define_method_id(mrb, mrb_ares_class, MRB_SYM(timeout),           mrb_ares_timeout,               MRB_ARGS_OPT(1));
  mrb_define_method_id(mrb, mrb_ares_class, MRB_SYM(process_fd),        mrb_ares_process_fd,            MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, mrb_ares_class, MRB_SYM(servers_ports_csv),mrb_ares_set_servers_ports_csv, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, mrb_ares_class, MRB_SYM(local_ip4),        mrb_ares_set_local_ip4,         MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, mrb_ares_class, MRB_SYM(local_ip6),        mrb_ares_set_local_ip6,         MRB_ARGS_REQ(1));
  mrb_ares_options_class = mrb_define_class_under_id(mrb, mrb_ares_class, MRB_SYM(Options), mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_options_class, MRB_TT_CDATA);
  mrb_undef_method_id(mrb, mrb_ares_class, MRB_SYM(initialize_copy));
  mrb_undef_method_id(mrb, mrb_ares_options_class, MRB_SYM(initialize_copy));
  mrb_value available_options = mrb_ary_new(mrb);
  mrb_define_const_id (mrb, mrb_ares_options_class, MRB_SYM(AVAILABLE_OPTIONS), available_options);
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(initialize),      mrb_ares_options_new,                 MRB_ARGS_NONE());
#ifdef ARES_OPT_FLAGS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(flags)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(flags),           mrb_ares_options_flags_get,           MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(flags),          mrb_ares_options_flags_set,           MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_TIMEOUTMS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(timeout)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(timeout),         mrb_ares_options_timeout_get,         MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(timeout),        mrb_ares_options_timeout_set,         MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_TRIES
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(tries)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(tries),           mrb_ares_options_tries_get,           MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(tries),          mrb_ares_options_tries_set,           MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_NDOTS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(ndots)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(ndots),           mrb_ares_options_ndots_get,           MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(ndots),          mrb_ares_options_ndots_set,           MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_DOMAINS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(domains)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(domains),     mrb_ares_options_domains_set,         MRB_ARGS_ANY());
#endif
#ifdef ARES_OPT_EDNSPSZ
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(ednspsz)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(ednspsz),         mrb_ares_options_ednspsz_get,         MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(ednspsz),        mrb_ares_options_ednspsz_set,         MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_RESOLVCONF
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(resolvconf_path)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(resolvconf_path),mrb_ares_options_resolvconf_path_set, MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_HOSTS_FILE
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(hosts_path)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(hosts_path),     mrb_ares_options_hosts_path_set,      MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_UDP_MAX_QUERIES
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(udp_max_queries)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(udp_max_queries), mrb_ares_options_udp_max_queries_get, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(udp_max_queries),mrb_ares_options_udp_max_queries_set, MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_MAXTIMEOUTMS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(maxtimeout)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(maxtimeout),      mrb_ares_options_maxtimeout_get,      MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(maxtimeout),     mrb_ares_options_maxtimeout_set,      MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_QUERY_CACHE
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(qcache_max_ttl)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(qcache_max_ttl),  mrb_ares_options_qcache_max_ttl_get,  MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM_E(qcache_max_ttl), mrb_ares_options_qcache_max_ttl_set,  MRB_ARGS_REQ(1));
#endif
  mrb_obj_freeze(mrb, available_options);
}

void
mrb_mruby_c_ares_gem_init(mrb_state* mrb)
{
  mrb_cares_bootstrap(mrb);
  mrb_cares_register_ruby(mrb);
}

void
mrb_mruby_c_ares_gem_final(mrb_state* mrb)
{
  ares_library_cleanup();
#ifdef _WIN32
  WSACleanup();
#endif
}
MRB_END_DECL