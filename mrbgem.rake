require_relative 'src/const_gen.rb'
MRuby::Gem::Specification.new('mruby-c-ares') do |spec|

  build_root   = "#{spec.build_dir}/build"
  install_lib  = "#{build_root}/lib/libcares.a"
  install_hdr  = "#{build_root}/include/ares.h"

  FileUtils.mkdir_p(build_root)

  # A partial previous build (header installed but the lib build failed, or
  # vice versa) must be retried, so only skip when both artifacts exist.
  unless File.exist?(install_lib) && File.exist?(install_hdr)
    c_flags = spec.for_windows? ? "" : "-fPIE"
    build_type = spec.cc.defines.include?('MRB_DEBUG') ? "Debug" : "Release"

    build_cmd = [
      "cmake",
      "-DCMAKE_BUILD_TYPE=#{build_type}",
      "-DCARES_STATIC=On",
      "-DCARES_SHARED=Off",
      "-DCMAKE_C_FLAGS=#{c_flags}",
      "-DCMAKE_INSTALL_PREFIX=#{build_root}",
      "-DCMAKE_INSTALL_LIBDIR=lib",
      "#{spec.dir}/deps/c-ares/"
    ].join(" ")

    Dir.chdir(build_root) do
      sh build_cmd
      sh "cmake --build . --config #{build_type} --target install --parallel"
    end
  end

  # Linker flag (Windows uses `.lib`, Unix uses `.a`). With CARES_SHARED=Off
  # c-ares' CMake installs the static library as plain `cares.lib` on Windows
  # (the `_static` suffix only applies when the shared lib is built too).
  if spec.for_windows?
    spec.linker.flags_before_libraries << "#{build_root}/lib/cares.lib"
    spec.linker.libraries << 'ws2_32' << 'iphlpapi'
  else
    spec.linker.flags_before_libraries << install_lib
  end

  spec.cxx.include_paths << "#{build_root}/include"
  spec.cxx.include_paths << "#{spec.build_dir}/src"
  spec.cxx.defines << "CARES_STATICLIB"
  # MSVC needs an explicit standard for the designated initializers in src/
  spec.cxx.flags << '/std:c++20' if spec.cxx.command.to_s =~ /\bcl(\.exe)?\z/i
  spec.add_dependency 'mruby-socket'
  spec.add_dependency 'mruby-c-ext-helpers'
  # mruby-io-uring is Linux-only and nothing under test/ uses it (only
  # examples/io_uring.rb does), so it must not be a test dependency or
  # `rake test` breaks on every non-Linux platform.
  spec.add_test_dependency 'mruby-pack'

  spec.license = 'MIT'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Async DNS for mruby'
  const_gen(spec)
end
