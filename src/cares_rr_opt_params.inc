/* Ares::RROptParamMap - the EDNS(0) options and the SVCB parameters.
 *
 * Same shape as the field map above: the c-ares key, and the name the
 * parsed record carries in Ruby.
 */
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_SVCB_PARAM_MANDATORY),
  mrb_symbol_value(MRB_SYM(mandatory)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_SVCB_PARAM_ALPN),
  mrb_symbol_value(MRB_SYM(alpn)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_SVCB_PARAM_NO_DEFAULT_ALPN),
  mrb_symbol_value(MRB_SYM(no_default_alpn)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_SVCB_PARAM_PORT),
  mrb_symbol_value(MRB_SYM(port)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_SVCB_PARAM_IPV4HINT),
  mrb_symbol_value(MRB_SYM(ipv4hint)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_SVCB_PARAM_ECH),
  mrb_symbol_value(MRB_SYM(ech)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_SVCB_PARAM_IPV6HINT),
  mrb_symbol_value(MRB_SYM(ipv6hint)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_LLQ),
  mrb_symbol_value(MRB_SYM(llq)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_UL),
  mrb_symbol_value(MRB_SYM(ul)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_NSID),
  mrb_symbol_value(MRB_SYM(nsid)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_DAU),
  mrb_symbol_value(MRB_SYM(dau)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_DHU),
  mrb_symbol_value(MRB_SYM(dhu)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_N3U),
  mrb_symbol_value(MRB_SYM(n3u)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_EDNS_CLIENT_SUBNET),
  mrb_symbol_value(MRB_SYM(edns_client_subnet)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_EDNS_EXPIRE),
  mrb_symbol_value(MRB_SYM(edns_expire)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_COOKIE),
  mrb_symbol_value(MRB_SYM(cookie)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_EDNS_TCP_KEEPALIVE),
  mrb_symbol_value(MRB_SYM(edns_tcp_keepalive)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_PADDING),
  mrb_symbol_value(MRB_SYM(padding)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_CHAIN),
  mrb_symbol_value(MRB_SYM(chain)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_EDNS_KEY_TAG),
  mrb_symbol_value(MRB_SYM(edns_key_tag)));
mrb_hash_set(mrb, rr_opt_param_map,
  mrb_convert_number(mrb, ARES_OPT_PARAM_EXTENDED_DNS_ERROR),
  mrb_symbol_value(MRB_SYM(extended_dns_error)));
