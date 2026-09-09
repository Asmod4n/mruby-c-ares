/* Ares::RRFieldMap - every resource record field, by its c-ares key.
 *
 * The key is what ares_dns_rr_get_* answers to, and the symbol is the name
 * the parsed record carries in Ruby.
 */
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_A_ADDR),
  mrb_symbol_value(MRB_SYM(a_addr)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_NS_NSDNAME),
  mrb_symbol_value(MRB_SYM(ns_nsdname)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_CNAME_CNAME),
  mrb_symbol_value(MRB_SYM(cname_cname)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SOA_MNAME),
  mrb_symbol_value(MRB_SYM(soa_mname)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SOA_RNAME),
  mrb_symbol_value(MRB_SYM(soa_rname)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SOA_SERIAL),
  mrb_symbol_value(MRB_SYM(soa_serial)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SOA_REFRESH),
  mrb_symbol_value(MRB_SYM(soa_refresh)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SOA_RETRY),
  mrb_symbol_value(MRB_SYM(soa_retry)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SOA_EXPIRE),
  mrb_symbol_value(MRB_SYM(soa_expire)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SOA_MINIMUM),
  mrb_symbol_value(MRB_SYM(soa_minimum)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_PTR_DNAME),
  mrb_symbol_value(MRB_SYM(ptr_dname)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_HINFO_CPU),
  mrb_symbol_value(MRB_SYM(hinfo_cpu)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_HINFO_OS),
  mrb_symbol_value(MRB_SYM(hinfo_os)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_MX_PREFERENCE),
  mrb_symbol_value(MRB_SYM(mx_preference)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_MX_EXCHANGE),
  mrb_symbol_value(MRB_SYM(mx_exchange)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_TXT_DATA),
  mrb_symbol_value(MRB_SYM(txt_data)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SIG_TYPE_COVERED),
  mrb_symbol_value(MRB_SYM(sig_type_covered)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SIG_ALGORITHM),
  mrb_symbol_value(MRB_SYM(sig_algorithm)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SIG_LABELS),
  mrb_symbol_value(MRB_SYM(sig_labels)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SIG_ORIGINAL_TTL),
  mrb_symbol_value(MRB_SYM(sig_original_ttl)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SIG_EXPIRATION),
  mrb_symbol_value(MRB_SYM(sig_expiration)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SIG_INCEPTION),
  mrb_symbol_value(MRB_SYM(sig_inception)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SIG_KEY_TAG),
  mrb_symbol_value(MRB_SYM(sig_key_tag)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SIG_SIGNERS_NAME),
  mrb_symbol_value(MRB_SYM(sig_signers_name)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SIG_SIGNATURE),
  mrb_symbol_value(MRB_SYM(sig_signature)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_AAAA_ADDR),
  mrb_symbol_value(MRB_SYM(aaaa_addr)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SRV_PRIORITY),
  mrb_symbol_value(MRB_SYM(srv_priority)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SRV_WEIGHT),
  mrb_symbol_value(MRB_SYM(srv_weight)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SRV_PORT),
  mrb_symbol_value(MRB_SYM(srv_port)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SRV_TARGET),
  mrb_symbol_value(MRB_SYM(srv_target)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_NAPTR_ORDER),
  mrb_symbol_value(MRB_SYM(naptr_order)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_NAPTR_PREFERENCE),
  mrb_symbol_value(MRB_SYM(naptr_preference)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_NAPTR_FLAGS),
  mrb_symbol_value(MRB_SYM(naptr_flags)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_NAPTR_SERVICES),
  mrb_symbol_value(MRB_SYM(naptr_services)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_NAPTR_REGEXP),
  mrb_symbol_value(MRB_SYM(naptr_regexp)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_NAPTR_REPLACEMENT),
  mrb_symbol_value(MRB_SYM(naptr_replacement)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_OPT_UDP_SIZE),
  mrb_symbol_value(MRB_SYM(opt_udp_size)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_OPT_VERSION),
  mrb_symbol_value(MRB_SYM(opt_version)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_OPT_FLAGS),
  mrb_symbol_value(MRB_SYM(opt_flags)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_OPT_OPTIONS),
  mrb_symbol_value(MRB_SYM(opt_options)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_TLSA_CERT_USAGE),
  mrb_symbol_value(MRB_SYM(tlsa_cert_usage)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_TLSA_SELECTOR),
  mrb_symbol_value(MRB_SYM(tlsa_selector)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_TLSA_MATCH),
  mrb_symbol_value(MRB_SYM(tlsa_match)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_TLSA_DATA),
  mrb_symbol_value(MRB_SYM(tlsa_data)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SVCB_PRIORITY),
  mrb_symbol_value(MRB_SYM(svcb_priority)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SVCB_TARGET),
  mrb_symbol_value(MRB_SYM(svcb_target)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_SVCB_PARAMS),
  mrb_symbol_value(MRB_SYM(svcb_params)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_HTTPS_PRIORITY),
  mrb_symbol_value(MRB_SYM(https_priority)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_HTTPS_TARGET),
  mrb_symbol_value(MRB_SYM(https_target)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_HTTPS_PARAMS),
  mrb_symbol_value(MRB_SYM(https_params)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_URI_PRIORITY),
  mrb_symbol_value(MRB_SYM(uri_priority)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_URI_WEIGHT),
  mrb_symbol_value(MRB_SYM(uri_weight)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_URI_TARGET),
  mrb_symbol_value(MRB_SYM(uri_target)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_CAA_CRITICAL),
  mrb_symbol_value(MRB_SYM(caa_critical)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_CAA_TAG),
  mrb_symbol_value(MRB_SYM(caa_tag)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_CAA_VALUE),
  mrb_symbol_value(MRB_SYM(caa_value)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_RAW_RR_TYPE),
  mrb_symbol_value(MRB_SYM(raw_rr_type)));
mrb_hash_set(mrb, rr_field_map,
  mrb_convert_number(mrb, ARES_RR_RAW_RR_DATA),
  mrb_symbol_value(MRB_SYM(raw_rr_data)));
