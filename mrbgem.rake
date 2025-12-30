require_relative 'src/const_gen.rb'
MRuby::Gem::Specification.new('mruby-c-ares') do |spec|

  build_root   = "#{spec.build_dir}/build"
  install_lib  = "#{build_root}/lib64/libcares.a"
  install_hdr  = "#{build_root}/include/ares.h"

  FileUtils.mkdir_p(build_root)

  unless File.exist?(install_lib) || File.exist?(install_hdr)
    # Detect compiler from environment or fallback to platform
    compiler = spec.cc.command
    use_pie = compiler.include?("clang") || compiler.include?("gcc")

    c_flags = use_pie ? "-fPIE" : ""
    build_type = spec.cc.defines.include?('MRB_DEBUG') ? "Debug" : "Release"

    build_cmd = [
      "cmake",
      "-DCMAKE_BUILD_TYPE=#{build_type}",
      "-DCARES_STATIC=On",
      "-DCARES_SHARED=Off",
      "-DCMAKE_C_FLAGS=#{c_flags}",
      "-DCMAKE_INSTALL_PREFIX=#{build_root}",
      "#{spec.dir}/deps/c-ares/"
    ].join(" ")

    Dir.chdir(build_root) do
      sh build_cmd
      if spec.for_windows?
        sh "cmake --build . --config #{build_type} --target install"
      else
        sh "make -j16 && make install"
      end
    end
  end

  # Linker flag (Windows uses `.lib`, Unix uses `.a`)
  if spec.for_windows?
    spec.linker.flags_before_libraries << "#{build_root}/lib/libcares.lib"
  else
    spec.linker.flags_before_libraries << install_lib
  end

  spec.cxx.include_paths << "#{build_root}/include"
  spec.cxx.include_paths << "#{spec.build_dir}/src"
  spec.cxx.defines << "CARES_STATICLIB"
  spec.add_dependency 'mruby-socket'
  spec.add_test_dependency 'mruby-io-uring'

  spec.license = 'MIT'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Async DNS for mruby'
  const_gen(spec)
end
