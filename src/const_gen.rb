def const_gen(spec)
  FileUtils.mkdir_p("#{spec.build_dir}/src/")
  d = File.open("#{spec.build_dir}/src/cares_const.cstub", "w+")
  spec.cxx.defines << "CARES_CONST_CSTUB=\\\"#{d.path}\\\""

  define_match = /^[ \t]*#define ARES_(\S+)[ \t]*((?:.*\\\r?\n)*.*)/m
  IO.readlines(spec.cc.search_header('ares.h')).each do |line|
    if (match = define_match.match(line))
      next if (match[1] ==  "_H")
      next if (match[1] == "GETSOCK_READABLE(bits,")
      next if (match[1] == "GETSOCK_WRITABLE(bits,")
      d.write <<-C
mrb_cares_define_const(MRB_SYM(#{match[1]}), ARES_#{match[1]});
C
    end
  end

  header_content = File.read(spec.cc.search_header('ares.h'))

  header_content = header_content.gsub(/\/\/.*|\/\*.*?\*\//m, '')

  ares_status = header_content.match(/typedef\s+enum\s*\{([^}]+)\}\s*ares_status_t;/)

  d = File.open("#{spec.build_dir}/src/cares_enums.cstub", 'w')
  spec.cxx.defines << "CARES_ENUMS_CSTUB=\\\"#{d.path}\\\""
  ares_status[1].split(',').each do |value|
    key, val = value.split(' = ')
    if (key && val != "0")
      key = key.gsub(/[^a-zA-Z0-9_]/, '')
      d.write <<-C
mrb_cares_define_ares_status(MRB_SYM(#{key[5..-1]}), #{key});
C
    end
  end

  header_content = File.read(spec.cc.search_header('ares_dns_record.h'))

  header_content = header_content.gsub(/\/\/.*|\/\*.*?\*\//m, '')

  ares_dns_rec_type = header_content.match(/typedef\s+enum\s*\{([^}]+)\}\s*ares_dns_rec_type_t;/)
  ares_dns_rec_type[1].split(',').each do |value|
    key, val = value.split(' = ')
    if (key && val != "0")
      key = key.gsub(/[^a-zA-Z0-9_]/, '')
      d.write <<-C
mrb_cares_define_ares_dns_rec_type(MRB_SYM(#{key[14..-1]}), #{key});
C
    end
  end

  ares_dns_class_type = header_content.match(/typedef\s+enum\s*\{([^}]+)\}\s*ares_dns_class_t;/)
  ares_dns_class_type[1].split(',').each do |value|
    key, val = value.split(' = ')
    if (key && val != "0")
      key = key.gsub(/[^a-zA-Z0-9_]/, '')
      d.write <<-C
mrb_cares_define_ares_dns_class_type(MRB_SYM(#{key[11..-1]}), #{key});
C
    end
  end

  rr_stub = File.open("#{spec.build_dir}/src/cares_rr_fields.cstub", "w")
  spec.cxx.defines << "CARES_RR_FIELDS_CSTUB=\\\"#{rr_stub.path}\\\""

  rr_keys = header_content.scan(/(ARES_RR_[A-Z0-9_]+)/).flatten.uniq

  rr_keys.each do |key|
    sym = key.sub(/^ARES_RR_/, '').downcase
    rr_stub.write <<-C
  mrb_hash_set(mrb, rr_field_map,
    mrb_convert_number(mrb, #{key}),
    mrb_symbol_value(MRB_SYM(#{sym}))
  );
  C
  end


  opt_stub = File.open("#{spec.build_dir}/src/cares_rr_opt_params.cstub", "w")
  spec.cxx.defines << "CARES_RR_OPT_PARAMS_CSTUB=\\\"#{opt_stub.path}\\\""

  opt_keys = header_content.scan(/(ARES_(?:OPT|SVCB)_PARAM_[A-Z0-9_]+)/).flatten.uniq

  opt_keys.each do |key|
    sym = key.sub(/^ARES_(?:OPT|SVCB)_PARAM_/, '').downcase
    opt_stub.write <<-C
  mrb_hash_set(mrb, rr_opt_param_map,
    mrb_convert_number(mrb, #{key}),
    mrb_symbol_value(MRB_SYM(#{sym}))
  );
  C
  end


end
