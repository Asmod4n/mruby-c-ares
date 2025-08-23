MRuby::Gem::Specification.new('mruby-c-ares') do |spec|

  FileUtils.mkdir_p("#{spec.build_dir}/build/")

  build_cmd = [
    "cmake",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCARES_STATIC=On",
    "-DCARES_SHARED=Off",
    "-DCMAKE_INSTALL_PREFIX=#{spec.build_dir}/build/",
    "#{spec.dir}/deps/c-ares/"
  ].join(" ")

  Dir.chdir("#{spec.build_dir}/build") do
    sh build_cmd
    if spec.for_windows?
      sh "cmake --build . --config Release --target install"
    else
      sh "make -j16 && make install"
    end
  end

  # Linker flag (Windows uses `.lib`, Unix uses `.a`)
  if spec.for_windows?
    spec.linker.flags_before_libraries << "#{spec.build_dir}/build/lib/libcares.lib"
  else
    spec.linker.flags_before_libraries << "#{spec.build_dir}/build/lib64/libcares.a"
  end

  spec.cc.include_paths << "#{spec.build_dir}/build/include"
  spec.cc.defines << "CARES_STATICLIB"
  spec.add_dependency 'mruby-c-ext-helpers'
  spec.add_dependency 'mruby-socket'

  spec.license = 'MIT'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Async DNS for mruby'

end
