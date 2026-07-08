MRUBY_CONFIG=File.expand_path(ENV["MRUBY_CONFIG"] || "build_config.rb")

file :mruby do
  sh "git clone --depth=1 https://github.com/mruby/mruby.git"
end

desc "build only (no tests)"
task :build => :mruby do
  sh({"MRUBY_CONFIG" => MRUBY_CONFIG}, "rake all", chdir: "mruby")
end

desc "test"
task :test => :mruby do
  # env hash + chdir instead of `cd x && VAR=val ...` so this also works
  # under cmd.exe on Windows
  sh({"MRUBY_CONFIG" => MRUBY_CONFIG}, "rake all test", chdir: "mruby")
end

desc "cleanup"
task :clean do
  sh "rake deep_clean", chdir: "mruby"
end

desc "constgen"
task :constgen do
  sh "ruby src/const_gen.rb"
end

task :default => :test
