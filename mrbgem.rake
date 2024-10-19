MRuby::Gem::Specification.new('mruby-c-ares') do |spec|
  unless spec.search_package('libcares')
    raise "mruby-c-ares: can't find c-ares libraries or development headers, please install them."
  end
  def const_gen(spec)

    d = File.open("#{spec.build_dir}/src/cares_const.cstub", "w")
    spec.cc.defines << "CARES_CONST_CSTUB=\\\"#{d.path}\\\""

    define_match = /^[ \t]*#define ARES_(\S+)[ \t]*((?:.*\\\r?\n)*.*)/m
    IO.readlines(spec.cc.search_header('ares.h')).each do |line|
      if (match = define_match.match(line))
        next if (match[1] ==  "_H")
        next if (match[1] == "GETSOCK_READABLE(bits,")
        next if (match[1] == "GETSOCK_WRITABLE(bits,")
        d.write <<-C
mrb_cares_define_const("#{match[1]}", ARES_#{match[1]});
C
      end
    end

    header_content = File.read(spec.cc.search_header('ares.h'))

    header_content = header_content.gsub(/\/\/.*|\/\*.*?\*\//m, '')

    ares_status = header_content.match(/typedef\s+enum\s*\{([^}]+)\}\s*ares_status_t;/)

    d = File.open("#{spec.build_dir}/src/cares_enums.cstub", 'w')
    spec.cc.defines << "CARES_ENUMS_CSTUB=\\\"#{d.path}\\\""
    ares_status[1].split(',').each do |value|
      key, val = value.split(' = ')
      if (key && val != "0")
        key = key.gsub(/[^a-zA-Z0-9_]/, '')
        d.write <<-C
mrb_cares_define_ares_status("#{key[5..-1]}", #{key});
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
mrb_cares_define_ares_dns_rec_type("#{key[14..-1]}", #{key});
C
      end
    end

  end

  spec.add_dependency 'mruby-socket'

  spec.license = 'MIT'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Async DNS for mruby'

  const_gen(spec)
end
