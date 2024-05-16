#define _DEFAULT_SOURCE
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

#include <mruby.h>
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
#include <mruby/throw.h>

#include <ares.h>
#if !((ARES_VERSION_MAJOR == 1 && ARES_VERSION_MINOR >= 16) || ARES_VERSION_MAJOR > 1)
#error "mruby-c-ares needs at least c-ares Version 1.16.0"
#endif

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
  struct RClass *addrinfo_class;
  struct RClass *cares_args_class;
  mrb_value cares;
  mrb_value block;
  ares_channel channel;
  mrb_bool destruction;
};

struct mrb_cares_args {
  struct mrb_cares_ctx *mrb_cares_ctx;
  mrb_value block;
  mrb_sym obj_id;
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
  mrb_value errno_to_class = mrb_const_get(mrb, mrb_obj_value(mrb_class_get(mrb, "Ares")), mrb_intern_lit(mrb, "_Errno2Class"));
  mrb_value errno_class = mrb_hash_get(mrb, errno_to_class, mrb_int_value(mrb, rc));
  if (mrb_nil_p(errno_class)) {
    mrb_raisef(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "Ares"), "Error"), "%s: %s", funcname, ares_strerror(rc));
  } else {
    mrb_raisef(mrb, mrb_class_ptr(errno_class), "%s: %s", funcname, ares_strerror(rc));
  }
}

static mrb_value
mrb_cares_response_error(mrb_state *mrb, int status)
{
  mrb_value errno_to_class = mrb_const_get(mrb, mrb_obj_value(mrb_class_get(mrb, "Ares")), mrb_intern_lit(mrb, "_Errno2Class"));
  mrb_value errno_class = mrb_hash_get(mrb, errno_to_class, mrb_int_value(mrb, status));
  if (mrb_nil_p(errno_class)) {
    return mrb_exc_new_str(mrb, mrb_class_get_under(mrb, mrb_class_get(mrb, "Ares"), "Error"), mrb_str_new_cstr(mrb, ares_strerror(status)));
  } else {
    return mrb_exc_new_str(mrb, mrb_class_ptr(errno_class), mrb_str_new_cstr(mrb, ares_strerror(status)));
  } 
}