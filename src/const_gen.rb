#!/usr/bin/env ruby

Dir.chdir(File.dirname($0))

d = File.open("cares_const.cstub", "w")

define_match = /^[ \t]*#define ARES_(\S+)[ \t]*((?:.*\\\r?\n)*.*)/m
IO.readlines(File.read('cares_h')).each do |line|
  if (match = define_match.match(line))
    next if (match[1] ==  "_H")
    next if (match[1] == "GETSOCK_READABLE(bits,")
    next if (match[1] == "GETSOCK_WRITABLE(bits,")
    d.write <<-C
#ifdef ARES_#{match[1]}
mrb_cares_define_const("#{match[1]}", ARES_#{match[1]});
#endif
C
  end
end

header_content = File.read(File.read('cares_h'))

header_content = header_content.gsub(/\/\/.*|\/\*.*?\*\//m, '')

ares_status = header_content.match(/typedef\s+enum\s*\{([^}]+)\}\s*ares_status_t;/)

d = File.open('cares_enums.cstub', 'w')
ares_status[1].split(',').each do |value|
  key, val = value.split(' = ')
  if (key && val != "0")
    key = key.gsub(/[^a-zA-Z0-9_]/, '')
    d.write <<-C
mrb_cares_define_ares_status("#{key[5..-1]}", #{key});
C
  end
end

header_content = File.read(File.read('cares_dns_record_h'))

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
