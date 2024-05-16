MRuby::Gem::Specification.new('mruby-c-ares') do |spec|
  unless spec.search_package('libcares')
    raise "mruby-c-ares: can't find c-ares libraries or development headers, please install them."
  end
  File.write("#{spec.dir}/src/cares_h", spec.cc.search_header('ares.h'))
  File.write("#{spec.dir}/src/cares_dns_record_h", spec.cc.search_header('ares_dns_record.h'))

  spec.add_dependency 'mruby-socket'

  spec.license = 'MIT'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Async DNS for mruby'
end
