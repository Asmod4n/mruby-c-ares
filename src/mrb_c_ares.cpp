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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) DATA_PTR(self);
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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) DATA_PTR(self);
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

/* ==========================================================================
 *  Helper parsers for individual RR types
 *  (accessors chosen according to ares_dns_rr_key_t datatypes)
 * ========================================================================== */

static void
mrb_ares_parse_rr_a(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  const struct in_addr *a4 = ares_dns_rr_get_addr(rr, ARES_RR_A_ADDR);
  if (!a4) return;

  char buf[INET_ADDRSTRLEN];
  if (!inet_ntop(AF_INET, a4, buf, sizeof(buf))) return;

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(address)),
    mrb_str_new_cstr(mrb, buf));
}

static void
mrb_ares_parse_rr_ns(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  const char *ns = ares_dns_rr_get_str(rr, ARES_RR_NS_NSDNAME);
  if (!ns) return;

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(ns)),
    mrb_str_new_cstr(mrb, ns));
}

static void
mrb_ares_parse_rr_cname(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  const char *cname = ares_dns_rr_get_str(rr, ARES_RR_CNAME_CNAME);
  if (!cname) return;

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(cname)),
    mrb_str_new_cstr(mrb, cname));
}

static void
mrb_ares_parse_rr_soa(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  const char *mname = ares_dns_rr_get_str(rr, ARES_RR_SOA_MNAME);
  const char *rname = ares_dns_rr_get_str(rr, ARES_RR_SOA_RNAME);

  if (mname) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(mname)),
      mrb_str_new_cstr(mrb, mname));
  }

  if (rname) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(rname)),
      mrb_str_new_cstr(mrb, rname));
  }

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(serial)),
    mrb_convert_number(mrb, ares_dns_rr_get_u32(rr, ARES_RR_SOA_SERIAL)));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(refresh)),
    mrb_convert_number(mrb, ares_dns_rr_get_u32(rr, ARES_RR_SOA_REFRESH)));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(retry)),
    mrb_convert_number(mrb, ares_dns_rr_get_u32(rr, ARES_RR_SOA_RETRY)));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(expire)),
    mrb_convert_number(mrb, ares_dns_rr_get_u32(rr, ARES_RR_SOA_EXPIRE)));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(minimum)),
    mrb_convert_number(mrb, ares_dns_rr_get_u32(rr, ARES_RR_SOA_MINIMUM)));
}

static void
mrb_ares_parse_rr_ptr(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  const char *ptr = ares_dns_rr_get_str(rr, ARES_RR_PTR_DNAME);
  if (!ptr) return;

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(ptr)),
    mrb_str_new_cstr(mrb, ptr));
}

static void
mrb_ares_parse_rr_hinfo(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  const char *cpu = ares_dns_rr_get_str(rr, ARES_RR_HINFO_CPU);
  const char *os  = ares_dns_rr_get_str(rr, ARES_RR_HINFO_OS);

  if (cpu) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(cpu)),
      mrb_str_new_cstr(mrb, cpu));
  }

  if (os) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(os)),
      mrb_str_new_cstr(mrb, os));
  }
}

static void
mrb_ares_parse_rr_mx(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned short pr = ares_dns_rr_get_u16(rr, ARES_RR_MX_PREFERENCE);
  const char *mx   = ares_dns_rr_get_str(rr, ARES_RR_MX_EXCHANGE);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(priority)),
    mrb_convert_number(mrb, pr));

  if (mx) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(host)),
      mrb_str_new_cstr(mrb, mx));
  }
}

static void
mrb_ares_parse_rr_txt(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  /* TXT: ABINP, but c-ares exposes printable form via get_str */
  const char *txt = ares_dns_rr_get_str(rr, ARES_RR_TXT_DATA);
  if (!txt) return;

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(texts)),
    mrb_str_new_cstr(mrb, txt));
}

static void
mrb_ares_parse_rr_sig(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned short type_covered = ares_dns_rr_get_u16(rr, ARES_RR_SIG_TYPE_COVERED);
  unsigned char  alg          = ares_dns_rr_get_u8(rr,  ARES_RR_SIG_ALGORITHM);
  unsigned char  labels       = ares_dns_rr_get_u8(rr,  ARES_RR_SIG_LABELS);
  unsigned int   orig_ttl     = ares_dns_rr_get_u32(rr, ARES_RR_SIG_ORIGINAL_TTL);
  unsigned int   expire       = ares_dns_rr_get_u32(rr, ARES_RR_SIG_EXPIRATION);
  unsigned int   inception    = ares_dns_rr_get_u32(rr, ARES_RR_SIG_INCEPTION);
  unsigned short key_tag      = ares_dns_rr_get_u16(rr, ARES_RR_SIG_KEY_TAG);
  const char    *signer       = ares_dns_rr_get_str(rr, ARES_RR_SIG_SIGNERS_NAME);

  size_t sig_len = 0;
  const unsigned char *sig =
    ares_dns_rr_get_bin(rr, ARES_RR_SIG_SIGNATURE, &sig_len);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(type_covered)),
    mrb_convert_number(mrb, type_covered));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(algorithm)),
    mrb_convert_number(mrb, alg));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(labels)),
    mrb_convert_number(mrb, labels));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(orig_ttl)),
    mrb_convert_number(mrb, orig_ttl));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(expiration)),
    mrb_convert_number(mrb, expire));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(inception)),
    mrb_convert_number(mrb, inception));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(key_tag)),
    mrb_convert_number(mrb, key_tag));

  if (signer) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(signer)),
      mrb_str_new_cstr(mrb, signer));
  }

  if (sig && sig_len > 0) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(signature)),
      mrb_str_new(mrb, (const char *)sig, (mrb_int)sig_len));
  }
}

static void
mrb_ares_parse_rr_aaaa(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  const struct ares_in6_addr *a6 = ares_dns_rr_get_addr6(rr, ARES_RR_AAAA_ADDR);
  if (!a6) return;

  char buf[INET6_ADDRSTRLEN];
  if (!inet_ntop(AF_INET6, a6, buf, sizeof(buf))) return;

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(address)),
    mrb_str_new_cstr(mrb, buf));
}

static void
mrb_ares_parse_rr_srv(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned short pr = ares_dns_rr_get_u16(rr, ARES_RR_SRV_PRIORITY);
  unsigned short wt = ares_dns_rr_get_u16(rr, ARES_RR_SRV_WEIGHT);
  unsigned short pt = ares_dns_rr_get_u16(rr, ARES_RR_SRV_PORT);
  const char    *t  = ares_dns_rr_get_str(rr, ARES_RR_SRV_TARGET);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(priority)),
    mrb_convert_number(mrb, pr));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(weight)),
    mrb_convert_number(mrb, wt));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(port)),
    mrb_convert_number(mrb, pt));

  if (t) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(host)),
      mrb_str_new_cstr(mrb, t));
  }
}

static void
mrb_ares_parse_rr_naptr(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned short order = ares_dns_rr_get_u16(rr, ARES_RR_NAPTR_ORDER);
  unsigned short pr    = ares_dns_rr_get_u16(rr, ARES_RR_NAPTR_PREFERENCE);

  const char *flags  = ares_dns_rr_get_str(rr, ARES_RR_NAPTR_FLAGS);
  const char *svc    = ares_dns_rr_get_str(rr, ARES_RR_NAPTR_SERVICES);
  const char *regexp = ares_dns_rr_get_str(rr, ARES_RR_NAPTR_REGEXP);
  const char *repl   = ares_dns_rr_get_str(rr, ARES_RR_NAPTR_REPLACEMENT);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(order)),
    mrb_convert_number(mrb, order));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(priority)),
    mrb_convert_number(mrb, pr));

  if (flags) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(flags)),
      mrb_str_new_cstr(mrb, flags));
  }

  if (svc) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(services)),
      mrb_str_new_cstr(mrb, svc));
  }

  if (regexp) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(regexp)),
      mrb_str_new_cstr(mrb, regexp));
  }

  if (repl) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(replacement)),
      mrb_str_new_cstr(mrb, repl));
  }
}

static void
mrb_ares_parse_rr_opt(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned short udp_size = ares_dns_rr_get_u16(rr, ARES_RR_OPT_UDP_SIZE);
  unsigned char  ver      = ares_dns_rr_get_u8(rr,  ARES_RR_OPT_VERSION);
  unsigned short flags    = ares_dns_rr_get_u16(rr, ARES_RR_OPT_FLAGS);
  const char    *opts     = ares_dns_rr_get_str(rr, ARES_RR_OPT_OPTIONS);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(udp_size)),
    mrb_convert_number(mrb, udp_size));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(version)),
    mrb_convert_number(mrb, ver));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(flags)),
    mrb_convert_number(mrb, flags));

  if (opts) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(options)),
      mrb_str_new_cstr(mrb, opts));
  }
}

static void
mrb_ares_parse_rr_tlsa(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned char usage    = ares_dns_rr_get_u8(rr, ARES_RR_TLSA_CERT_USAGE);
  unsigned char selector = ares_dns_rr_get_u8(rr, ARES_RR_TLSA_SELECTOR);
  unsigned char mtype    = ares_dns_rr_get_u8(rr, ARES_RR_TLSA_MATCH);

  size_t len = 0;
  const unsigned char *data =
    ares_dns_rr_get_bin(rr, ARES_RR_TLSA_DATA, &len);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(usage)),
    mrb_convert_number(mrb, usage));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(selector)),
    mrb_convert_number(mrb, selector));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(mtype)),
    mrb_convert_number(mrb, mtype));

  if (data && len > 0) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(data)),
      mrb_str_new(mrb, (const char *)data, (mrb_int)len));
  }
}

static void
mrb_ares_parse_rr_svcb(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned short pr = ares_dns_rr_get_u16(rr, ARES_RR_SVCB_PRIORITY);
  const char    *target = ares_dns_rr_get_str(rr, ARES_RR_SVCB_TARGET);
  const char    *params = ares_dns_rr_get_str(rr, ARES_RR_SVCB_PARAMS);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(priority)),
    mrb_convert_number(mrb, pr));

  if (target) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(target)),
      mrb_str_new_cstr(mrb, target));
  }

  if (params) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(params)),
      mrb_str_new_cstr(mrb, params));
  }
}

static void
mrb_ares_parse_rr_https(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned short pr = ares_dns_rr_get_u16(rr, ARES_RR_HTTPS_PRIORITY);
  const char    *target = ares_dns_rr_get_str(rr, ARES_RR_HTTPS_TARGET);
  const char    *params = ares_dns_rr_get_str(rr, ARES_RR_HTTPS_PARAMS);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(priority)),
    mrb_convert_number(mrb, pr));

  if (target) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(target)),
      mrb_str_new_cstr(mrb, target));
  }

  if (params) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(params)),
      mrb_str_new_cstr(mrb, params));
  }
}

static void
mrb_ares_parse_rr_uri(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned short pr = ares_dns_rr_get_u16(rr, ARES_RR_URI_PRIORITY);
  unsigned short wt = ares_dns_rr_get_u16(rr, ARES_RR_URI_WEIGHT);
  const char    *uri = ares_dns_rr_get_str(rr, ARES_RR_URI_TARGET);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(priority)),
    mrb_convert_number(mrb, pr));

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(weight)),
    mrb_convert_number(mrb, wt));

  if (uri) {
    mrb_value uri_str = mrb_str_new_cstr(mrb, uri);

    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(uri)),
      uri_str);

    mrb_value uri_class = mrb_obj_value(mrb_class_get_id(mrb, MRB_SYM(URI)));
    mrb_value parsed = mrb_funcall_argv(mrb, uri_class, MRB_SYM(parse), 1, &uri_str);

    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(parsed)),
      parsed);
  }
}

static void
mrb_ares_parse_rr_caa(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned char critical = ares_dns_rr_get_u8(rr, ARES_RR_CAA_CRITICAL);
  const char   *tag      = ares_dns_rr_get_str(rr, ARES_RR_CAA_TAG);

  size_t len = 0;
  const unsigned char *val =
    ares_dns_rr_get_bin(rr, ARES_RR_CAA_VALUE, &len);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(critical)),
    mrb_convert_number(mrb, critical));

  if (tag) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(tag)),
      mrb_str_new_cstr(mrb, tag));
  }

  if (val && len > 0) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(value)),
      mrb_str_new(mrb, (const char *)val, (mrb_int)len));
  }
}

static void
mrb_ares_parse_rr_raw(mrb_state *mrb, mrb_value hash, const ares_dns_rr_t *rr)
{
  unsigned short rrtype = ares_dns_rr_get_u16(rr, ARES_RR_RAW_RR_TYPE);

  size_t len = 0;
  const unsigned char *data =
    ares_dns_rr_get_bin(rr, ARES_RR_RAW_RR_DATA, &len);

  mrb_hash_set(mrb, hash,
    mrb_symbol_value(MRB_SYM(rrtype)),
    mrb_convert_number(mrb, rrtype));

  if (data && len > 0) {
    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(raw)),
      mrb_str_new(mrb, (const char *)data, (mrb_int)len));
  }
}

/* ==========================================================================
 *  Main parser: mrb_ares_parse_dnsrec_list
 * ========================================================================== */

static void
mrb_ares_parse_dnsrec_list(mrb_state *mrb, struct mrb_cares_args *args,
                           mrb_value argv[3], const ares_dns_record_t *rec_root)
{
  size_t cnt = ares_dns_record_rr_cnt(rec_root, ARES_SECTION_ANSWER);
  mrb_value ary = mrb_ary_new_capa(mrb, (mrb_int)cnt);

  for (size_t i = 0; i < cnt; ++i) {
    const ares_dns_rr_t *rr =
      ares_dns_record_rr_get_const(rec_root, ARES_SECTION_ANSWER, i);
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

    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(type)),
      mrb_cares_lookup_symbol(mrb, args, type, TRUE));

    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(class)),
      mrb_cares_lookup_symbol(mrb, args, cls, FALSE));

    mrb_hash_set(mrb, hash,
      mrb_symbol_value(MRB_SYM(ttl)),
      mrb_convert_number(mrb, ttl));

    switch (type) {
      case ARES_REC_TYPE_A:
        mrb_ares_parse_rr_a(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_NS:
        mrb_ares_parse_rr_ns(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_CNAME:
        mrb_ares_parse_rr_cname(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_SOA:
        mrb_ares_parse_rr_soa(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_PTR:
        mrb_ares_parse_rr_ptr(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_HINFO:
        mrb_ares_parse_rr_hinfo(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_MX:
        mrb_ares_parse_rr_mx(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_TXT:
        mrb_ares_parse_rr_txt(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_SIG:
        mrb_ares_parse_rr_sig(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_AAAA:
        mrb_ares_parse_rr_aaaa(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_SRV:
        mrb_ares_parse_rr_srv(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_NAPTR:
        mrb_ares_parse_rr_naptr(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_OPT:
        mrb_ares_parse_rr_opt(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_TLSA:
        mrb_ares_parse_rr_tlsa(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_SVCB:
        mrb_ares_parse_rr_svcb(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_HTTPS:
        mrb_ares_parse_rr_https(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_URI:
        mrb_ares_parse_rr_uri(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_CAA:
        mrb_ares_parse_rr_caa(mrb, hash, rr);
        break;

      case ARES_REC_TYPE_RAW_RR:
        mrb_ares_parse_rr_raw(mrb, hash, rr);
        break;

      default:
        mrb_raise(mrb, E_RUNTIME_ERROR, "unknown DNS Type");
        break;
    }

    mrb_ary_push(mrb, ary, hash);
  }

  argv[1] = ary;
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

  mrb_yield_argv(mrb, args->block, 3, argv);
  mrb_gc_arena_restore(mrb, idx);
}

//-------------------------------------------------------------------------
// 3) Entry point: query(name, :TYPE) { |timeouts, results, error| … }
//-------------------------------------------------------------------------
static mrb_value
mrb_ares_query(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_ctx *ctx =
    (struct mrb_cares_ctx*)DATA_PTR(self);
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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) DATA_PTR(self);
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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) DATA_PTR(self);

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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) DATA_PTR(self);
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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) DATA_PTR(self);
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
  struct mrb_cares_ctx *mrb_cares_ctx = (struct mrb_cares_ctx *) DATA_PTR(self);
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
  return mrb_convert_number(mrb, ((struct mrb_cares_options *)DATA_PTR(self))->options.flags);
}

static mrb_value
mrb_ares_options_flags_set(mrb_state *mrb, mrb_value self)
{
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);

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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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
  struct mrb_cares_options *mrb_cares_options = (struct mrb_cares_options *) DATA_PTR(self);
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

  mrb_ares_class = mrb_define_class_id(mrb, MRB_SYM(Ares), mrb->object_class);
  MRB_SET_INSTANCE_TT(mrb_ares_class, MRB_TT_CDATA);
  mrb_define_const_id (mrb, mrb_ares_class, MRB_SYM(VERSION),           mrb_str_new_lit_frozen(mrb, ARES_VERSION_STR));
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
  mrb_value available_options = mrb_ary_new(mrb);
  mrb_define_const_id (mrb, mrb_ares_options_class, MRB_SYM(AVAILABLE_OPTIONS), available_options);
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(initialize),      mrb_ares_options_new,                 MRB_ARGS_NONE());
#ifdef ARES_OPT_FLAGS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(flags)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(flags),           mrb_ares_options_flags_get,           MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(flags),          mrb_ares_options_flags_set,           MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_TIMEOUTMS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(timeout)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(timeout),         mrb_ares_options_timeout_get,         MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(timeout),        mrb_ares_options_timeout_set,         MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_TRIES
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(tries)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(tries),           mrb_ares_options_tries_get,           MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(tries),          mrb_ares_options_tries_set,           MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_NDOTS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(ndots)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(ndots),           mrb_ares_options_ndots_get,           MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(ndots),          mrb_ares_options_ndots_set,           MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_DOMAINS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(domains_set)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(domains_set),     mrb_ares_options_domains_set,         MRB_ARGS_ANY());
#endif
#ifdef ARES_OPT_EDNSPSZ
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(ednspsz)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(ednspsz),         mrb_ares_options_ednspsz_get,         MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(ednspsz),        mrb_ares_options_ednspsz_set,         MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_RESOLVCONF
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(resolvconf_path)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(resolvconf_path),mrb_ares_options_resolvconf_path_set, MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_HOSTS_FILE
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(hosts_path)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(hosts_path),     mrb_ares_options_hosts_path_set,      MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_UDP_MAX_QUERIES
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(udp_max_queries)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(udp_max_queries), mrb_ares_options_udp_max_queries_get, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(udp_max_queries),mrb_ares_options_udp_max_queries_set, MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_MAXTIMEOUTMS
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(maxtimeout)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(maxtimeout),      mrb_ares_options_maxtimeout_get,      MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(maxtimeout),     mrb_ares_options_maxtimeout_set,      MRB_ARGS_REQ(1));
#endif
#ifdef ARES_OPT_QUERY_CACHE
  mrb_ary_push(mrb, available_options, mrb_symbol_value(MRB_SYM(qcache_max_ttl)));
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(qcache_max_ttl),  mrb_ares_options_qcache_max_ttl_get,  MRB_ARGS_NONE());
  mrb_define_method_id(mrb, mrb_ares_options_class, MRB_SYM(qcache_max_ttl), mrb_ares_options_qcache_max_ttl_set,  MRB_ARGS_REQ(1));
#endif
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

  mrb_value rec_type_inv  = mrb_cares_build_inverse(mrb, rec_type);
  mrb_value class_inv     = mrb_cares_build_inverse(mrb, ares_dns_class);

  mrb_define_const_id(mrb, mrb_ares_class, MRB_SYM(RecTypeInverse), rec_type_inv);
  mrb_define_const_id(mrb, mrb_ares_class, MRB_SYM(DnsClassInverse), class_inv);


  mrb_obj_freeze(mrb, available_options);
  mrb_obj_freeze(mrb, errno_to_class);
  mrb_obj_freeze(mrb, rec_type);
  mrb_obj_freeze(mrb, ares_dns_class);
  mrb_obj_freeze(mrb, rec_type_inv);
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