/* ares_status_t, ares_dns_rec_type_t and ares_dns_class_t.
 *
 * Each status becomes an error class under Ares, so a failure reaches Ruby
 * as an object of its own type. ARES_SUCCESS is not among them: it is not
 * a failure and it has no class.
 * 
 * The record types and classes carry IANA wire numbers, so their values are
 * fixed by the protocol rather than by c-ares. The status codes are
 * c-ares's own, which is why they are named here and not numbered.
 */
mrb_cares_define_ares_status(MRB_SYM(ENODATA), ARES_ENODATA);
mrb_cares_define_ares_status(MRB_SYM(EFORMERR), ARES_EFORMERR);
mrb_cares_define_ares_status(MRB_SYM(ESERVFAIL), ARES_ESERVFAIL);
mrb_cares_define_ares_status(MRB_SYM(ENOTFOUND), ARES_ENOTFOUND);
mrb_cares_define_ares_status(MRB_SYM(ENOTIMP), ARES_ENOTIMP);
mrb_cares_define_ares_status(MRB_SYM(EREFUSED), ARES_EREFUSED);
mrb_cares_define_ares_status(MRB_SYM(EBADQUERY), ARES_EBADQUERY);
mrb_cares_define_ares_status(MRB_SYM(EBADNAME), ARES_EBADNAME);
mrb_cares_define_ares_status(MRB_SYM(EBADFAMILY), ARES_EBADFAMILY);
mrb_cares_define_ares_status(MRB_SYM(EBADRESP), ARES_EBADRESP);
mrb_cares_define_ares_status(MRB_SYM(ECONNREFUSED), ARES_ECONNREFUSED);
mrb_cares_define_ares_status(MRB_SYM(ETIMEOUT), ARES_ETIMEOUT);
mrb_cares_define_ares_status(MRB_SYM(EOF), ARES_EOF);
mrb_cares_define_ares_status(MRB_SYM(EFILE), ARES_EFILE);
mrb_cares_define_ares_status(MRB_SYM(ENOMEM), ARES_ENOMEM);
mrb_cares_define_ares_status(MRB_SYM(EDESTRUCTION), ARES_EDESTRUCTION);
mrb_cares_define_ares_status(MRB_SYM(EBADSTR), ARES_EBADSTR);
mrb_cares_define_ares_status(MRB_SYM(EBADFLAGS), ARES_EBADFLAGS);
mrb_cares_define_ares_status(MRB_SYM(ENONAME), ARES_ENONAME);
mrb_cares_define_ares_status(MRB_SYM(EBADHINTS), ARES_EBADHINTS);
mrb_cares_define_ares_status(MRB_SYM(ENOTINITIALIZED), ARES_ENOTINITIALIZED);
mrb_cares_define_ares_status(MRB_SYM(ELOADIPHLPAPI), ARES_ELOADIPHLPAPI);
mrb_cares_define_ares_status(MRB_SYM(EADDRGETNETWORKPARAMS), ARES_EADDRGETNETWORKPARAMS);
mrb_cares_define_ares_status(MRB_SYM(ECANCELLED), ARES_ECANCELLED);
mrb_cares_define_ares_status(MRB_SYM(ESERVICE), ARES_ESERVICE);
mrb_cares_define_ares_status(MRB_SYM(ENOSERVER), ARES_ENOSERVER);

mrb_cares_define_ares_dns_rec_type(MRB_SYM(A), ARES_REC_TYPE_A);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(NS), ARES_REC_TYPE_NS);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(CNAME), ARES_REC_TYPE_CNAME);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(SOA), ARES_REC_TYPE_SOA);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(PTR), ARES_REC_TYPE_PTR);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(HINFO), ARES_REC_TYPE_HINFO);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(MX), ARES_REC_TYPE_MX);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(TXT), ARES_REC_TYPE_TXT);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(SIG), ARES_REC_TYPE_SIG);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(AAAA), ARES_REC_TYPE_AAAA);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(SRV), ARES_REC_TYPE_SRV);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(NAPTR), ARES_REC_TYPE_NAPTR);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(OPT), ARES_REC_TYPE_OPT);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(TLSA), ARES_REC_TYPE_TLSA);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(SVCB), ARES_REC_TYPE_SVCB);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(HTTPS), ARES_REC_TYPE_HTTPS);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(ANY), ARES_REC_TYPE_ANY);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(URI), ARES_REC_TYPE_URI);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(CAA), ARES_REC_TYPE_CAA);
mrb_cares_define_ares_dns_rec_type(MRB_SYM(RAW_RR), ARES_REC_TYPE_RAW_RR);

mrb_cares_define_ares_dns_class_type(MRB_SYM(IN), ARES_CLASS_IN);
mrb_cares_define_ares_dns_class_type(MRB_SYM(CHAOS), ARES_CLASS_CHAOS);
mrb_cares_define_ares_dns_class_type(MRB_SYM(HESIOD), ARES_CLASS_HESIOD);
mrb_cares_define_ares_dns_class_type(MRB_SYM(HESOID), ARES_CLASS_HESOID);
mrb_cares_define_ares_dns_class_type(MRB_SYM(NONE), ARES_CLASS_NONE);
mrb_cares_define_ares_dns_class_type(MRB_SYM(ANY), ARES_CLASS_ANY);
