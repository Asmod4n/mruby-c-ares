def const_gen(spec)
  FileUtils.mkdir_p("#{spec.build_dir}/src/")

  strip_comments = ->(src) { src.gsub(/\/\/.*|\/\*.*?\*\//m, '') }
  extract_enum = lambda do |content, name|
    match = content.match(/typedef\s+enum\s*\{([^}]+)\}\s*#{Regexp.escape(name)};/)
    raise "const_gen: could not find enum #{name} — did the c-ares headers change format?" unless match
    match[1]
  end

  const_stub = "#{spec.build_dir}/src/cares_const.cstub"
  spec.cxx.defines << "CARES_CONST_CSTUB=\\\"#{const_stub}\\\""
  define_match = /^[ \t]*#define ARES_(\S+)[ \t]*((?:.*\\\r?\n)*.*)/m
  File.open(const_stub, "w") do |d|
    IO.readlines(spec.cxx.search_header('ares.h')).each do |line|
      if (match = define_match.match(line))
        next if (match[1] ==  "_H")
        next if (match[1] == "GETSOCK_READABLE(bits,")
        next if (match[1] == "GETSOCK_WRITABLE(bits,")
        d.write <<-C
mrb_cares_define_const(MRB_SYM(#{match[1]}), ARES_#{match[1]});
C
      end
    end
  end

  ares_h = strip_comments.call(File.read(spec.cxx.search_header('ares.h')))
  ares_dns_record_h = strip_comments.call(File.read(spec.cxx.search_header('ares_dns_record.h')))

  enum_entries = lambda do |body|
    body.split(',').filter_map do |value|
      key, val = value.split(' = ')
      next if key.nil? || val == "0"
      key.gsub(/[^a-zA-Z0-9_]/, '')
    end
  end

  enums_stub = "#{spec.build_dir}/src/cares_enums.cstub"
  spec.cxx.defines << "CARES_ENUMS_CSTUB=\\\"#{enums_stub}\\\""
  File.open(enums_stub, 'w') do |d|
    enum_entries.call(extract_enum.call(ares_h, 'ares_status_t')).each do |key|
      d.write <<-C
mrb_cares_define_ares_status(MRB_SYM(#{key.sub(/\AARES_/, '')}), #{key});
C
    end

    enum_entries.call(extract_enum.call(ares_dns_record_h, 'ares_dns_rec_type_t')).each do |key|
      d.write <<-C
mrb_cares_define_ares_dns_rec_type(MRB_SYM(#{key.sub(/\AARES_REC_TYPE_/, '')}), #{key});
C
    end

    enum_entries.call(extract_enum.call(ares_dns_record_h, 'ares_dns_class_t')).each do |key|
      d.write <<-C
mrb_cares_define_ares_dns_class_type(MRB_SYM(#{key.sub(/\AARES_CLASS_/, '')}), #{key});
C
    end
  end

  rr_stub_path = "#{spec.build_dir}/src/cares_rr_fields.cstub"
  spec.cxx.defines << "CARES_RR_FIELDS_CSTUB=\\\"#{rr_stub_path}\\\""
  rr_keys = ares_dns_record_h.scan(/(ARES_RR_[A-Z0-9_]+)/).flatten.uniq
  raise "const_gen: no ARES_RR_* keys found in ares_dns_record.h" if rr_keys.empty?
  File.open(rr_stub_path, "w") do |rr_stub|
    rr_keys.each do |key|
      sym = key.sub(/\AARES_RR_/, '').downcase
      rr_stub.write <<-C
  mrb_hash_set(mrb, rr_field_map,
    mrb_convert_number(mrb, #{key}),
    mrb_symbol_value(MRB_SYM(#{sym}))
  );
  C
    end
  end

  opt_stub_path = "#{spec.build_dir}/src/cares_rr_opt_params.cstub"
  spec.cxx.defines << "CARES_RR_OPT_PARAMS_CSTUB=\\\"#{opt_stub_path}\\\""
  opt_keys = ares_dns_record_h.scan(/(ARES_(?:OPT|SVCB)_PARAM_[A-Z0-9_]+)/).flatten.uniq
  raise "const_gen: no ARES_OPT/SVCB_PARAM_* keys found in ares_dns_record.h" if opt_keys.empty?
  File.open(opt_stub_path, "w") do |opt_stub|
    opt_keys.each do |key|
      sym = key.sub(/\AARES_(?:OPT|SVCB)_PARAM_/, '').downcase
      opt_stub.write <<-C
  mrb_hash_set(mrb, rr_opt_param_map,
    mrb_convert_number(mrb, #{key}),
    mrb_symbol_value(MRB_SYM(#{sym}))
  );
  C
    end
  end
end
