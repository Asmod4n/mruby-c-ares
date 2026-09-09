/* The ARES_* constants this gem publishes, one mrb_cares_define_const each.
 *
 * Written out rather than swept out of ares.h at build time. The value of
 * each one still comes from the header the build compiled against, because
 * the name is what is written here - so a c-ares too old to know one of
 * them is a compile error that says which, and not a constant that quietly
 * goes missing at run time.
 * 
 * ARES_GETSOCK_READABLE and ARES_GETSOCK_WRITABLE are not here: they take
 * arguments, so they are macros and not constants.
 */
mrb_cares_define_const(MRB_SYM(FLAG_USEVC), ARES_FLAG_USEVC);
mrb_cares_define_const(MRB_SYM(FLAG_PRIMARY), ARES_FLAG_PRIMARY);
mrb_cares_define_const(MRB_SYM(FLAG_IGNTC), ARES_FLAG_IGNTC);
mrb_cares_define_const(MRB_SYM(FLAG_NORECURSE), ARES_FLAG_NORECURSE);
mrb_cares_define_const(MRB_SYM(FLAG_STAYOPEN), ARES_FLAG_STAYOPEN);
mrb_cares_define_const(MRB_SYM(FLAG_NOSEARCH), ARES_FLAG_NOSEARCH);
mrb_cares_define_const(MRB_SYM(FLAG_NOALIASES), ARES_FLAG_NOALIASES);
mrb_cares_define_const(MRB_SYM(FLAG_NOCHECKRESP), ARES_FLAG_NOCHECKRESP);
mrb_cares_define_const(MRB_SYM(FLAG_EDNS), ARES_FLAG_EDNS);
mrb_cares_define_const(MRB_SYM(FLAG_NO_DFLT_SVR), ARES_FLAG_NO_DFLT_SVR);
mrb_cares_define_const(MRB_SYM(FLAG_DNS0x20), ARES_FLAG_DNS0x20);
mrb_cares_define_const(MRB_SYM(OPT_FLAGS), ARES_OPT_FLAGS);
mrb_cares_define_const(MRB_SYM(OPT_TIMEOUT), ARES_OPT_TIMEOUT);
mrb_cares_define_const(MRB_SYM(OPT_TRIES), ARES_OPT_TRIES);
mrb_cares_define_const(MRB_SYM(OPT_NDOTS), ARES_OPT_NDOTS);
mrb_cares_define_const(MRB_SYM(OPT_UDP_PORT), ARES_OPT_UDP_PORT);
mrb_cares_define_const(MRB_SYM(OPT_TCP_PORT), ARES_OPT_TCP_PORT);
mrb_cares_define_const(MRB_SYM(OPT_SERVERS), ARES_OPT_SERVERS);
mrb_cares_define_const(MRB_SYM(OPT_DOMAINS), ARES_OPT_DOMAINS);
mrb_cares_define_const(MRB_SYM(OPT_LOOKUPS), ARES_OPT_LOOKUPS);
mrb_cares_define_const(MRB_SYM(OPT_SOCK_STATE_CB), ARES_OPT_SOCK_STATE_CB);
mrb_cares_define_const(MRB_SYM(OPT_SORTLIST), ARES_OPT_SORTLIST);
mrb_cares_define_const(MRB_SYM(OPT_SOCK_SNDBUF), ARES_OPT_SOCK_SNDBUF);
mrb_cares_define_const(MRB_SYM(OPT_SOCK_RCVBUF), ARES_OPT_SOCK_RCVBUF);
mrb_cares_define_const(MRB_SYM(OPT_TIMEOUTMS), ARES_OPT_TIMEOUTMS);
mrb_cares_define_const(MRB_SYM(OPT_ROTATE), ARES_OPT_ROTATE);
mrb_cares_define_const(MRB_SYM(OPT_EDNSPSZ), ARES_OPT_EDNSPSZ);
mrb_cares_define_const(MRB_SYM(OPT_NOROTATE), ARES_OPT_NOROTATE);
mrb_cares_define_const(MRB_SYM(OPT_RESOLVCONF), ARES_OPT_RESOLVCONF);
mrb_cares_define_const(MRB_SYM(OPT_HOSTS_FILE), ARES_OPT_HOSTS_FILE);
mrb_cares_define_const(MRB_SYM(OPT_UDP_MAX_QUERIES), ARES_OPT_UDP_MAX_QUERIES);
mrb_cares_define_const(MRB_SYM(OPT_MAXTIMEOUTMS), ARES_OPT_MAXTIMEOUTMS);
mrb_cares_define_const(MRB_SYM(OPT_QUERY_CACHE), ARES_OPT_QUERY_CACHE);
mrb_cares_define_const(MRB_SYM(OPT_EVENT_THREAD), ARES_OPT_EVENT_THREAD);
mrb_cares_define_const(MRB_SYM(OPT_SERVER_FAILOVER), ARES_OPT_SERVER_FAILOVER);
mrb_cares_define_const(MRB_SYM(NI_NOFQDN), ARES_NI_NOFQDN);
mrb_cares_define_const(MRB_SYM(NI_NUMERICHOST), ARES_NI_NUMERICHOST);
mrb_cares_define_const(MRB_SYM(NI_NAMEREQD), ARES_NI_NAMEREQD);
mrb_cares_define_const(MRB_SYM(NI_NUMERICSERV), ARES_NI_NUMERICSERV);
mrb_cares_define_const(MRB_SYM(NI_DGRAM), ARES_NI_DGRAM);
mrb_cares_define_const(MRB_SYM(NI_TCP), ARES_NI_TCP);
mrb_cares_define_const(MRB_SYM(NI_UDP), ARES_NI_UDP);
mrb_cares_define_const(MRB_SYM(NI_SCTP), ARES_NI_SCTP);
mrb_cares_define_const(MRB_SYM(NI_DCCP), ARES_NI_DCCP);
mrb_cares_define_const(MRB_SYM(NI_NUMERICSCOPE), ARES_NI_NUMERICSCOPE);
mrb_cares_define_const(MRB_SYM(NI_LOOKUPHOST), ARES_NI_LOOKUPHOST);
mrb_cares_define_const(MRB_SYM(NI_LOOKUPSERVICE), ARES_NI_LOOKUPSERVICE);
mrb_cares_define_const(MRB_SYM(NI_IDN), ARES_NI_IDN);
mrb_cares_define_const(MRB_SYM(NI_IDN_ALLOW_UNASSIGNED), ARES_NI_IDN_ALLOW_UNASSIGNED);
mrb_cares_define_const(MRB_SYM(NI_IDN_USE_STD3_ASCII_RULES), ARES_NI_IDN_USE_STD3_ASCII_RULES);
mrb_cares_define_const(MRB_SYM(AI_CANONNAME), ARES_AI_CANONNAME);
mrb_cares_define_const(MRB_SYM(AI_NUMERICHOST), ARES_AI_NUMERICHOST);
mrb_cares_define_const(MRB_SYM(AI_PASSIVE), ARES_AI_PASSIVE);
mrb_cares_define_const(MRB_SYM(AI_NUMERICSERV), ARES_AI_NUMERICSERV);
mrb_cares_define_const(MRB_SYM(AI_V4MAPPED), ARES_AI_V4MAPPED);
mrb_cares_define_const(MRB_SYM(AI_ALL), ARES_AI_ALL);
mrb_cares_define_const(MRB_SYM(AI_ADDRCONFIG), ARES_AI_ADDRCONFIG);
mrb_cares_define_const(MRB_SYM(AI_NOSORT), ARES_AI_NOSORT);
mrb_cares_define_const(MRB_SYM(AI_ENVHOSTS), ARES_AI_ENVHOSTS);
mrb_cares_define_const(MRB_SYM(AI_IDN), ARES_AI_IDN);
mrb_cares_define_const(MRB_SYM(AI_IDN_ALLOW_UNASSIGNED), ARES_AI_IDN_ALLOW_UNASSIGNED);
mrb_cares_define_const(MRB_SYM(AI_IDN_USE_STD3_ASCII_RULES), ARES_AI_IDN_USE_STD3_ASCII_RULES);
mrb_cares_define_const(MRB_SYM(AI_CANONIDN), ARES_AI_CANONIDN);
mrb_cares_define_const(MRB_SYM(AI_MASK), ARES_AI_MASK);
mrb_cares_define_const(MRB_SYM(GETSOCK_MAXNUM), ARES_GETSOCK_MAXNUM);
mrb_cares_define_const(MRB_SYM(LIB_INIT_NONE), ARES_LIB_INIT_NONE);
mrb_cares_define_const(MRB_SYM(LIB_INIT_WIN32), ARES_LIB_INIT_WIN32);
mrb_cares_define_const(MRB_SYM(LIB_INIT_ALL), ARES_LIB_INIT_ALL);
mrb_cares_define_const(MRB_SYM(SERV_STATE_UDP), ARES_SERV_STATE_UDP);
mrb_cares_define_const(MRB_SYM(SERV_STATE_TCP), ARES_SERV_STATE_TCP);
