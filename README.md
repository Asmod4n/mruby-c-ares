# mruby-c-ares
Async DNS client for mruby

Requirements
============
You need to have the c-ares library with development headers installed for your target.

On debian based systems: ```apt install libc-ares libc-ares-dev```

On macOS with homebrew: ```brew install c-ares```

for other platforms it has most likely a c-ares name in it's package manager, if you can't find it in your package manager take a look at https://github.com/c-ares/c-ares/blob/main/INSTALL.md for building it yourself.

Installation
============
create a build_config.rb file and add gem mgem: 'mruby-c-ares' to it

Usage examples
==============

Currently only getaddrinfo is implemented, if you need more let me know!

requires 'mruby-poll' IO.select will be implemented later.
```ruby
poll = Poll.new
ares = Ares.new do |socket, readable, writable|
  poll.remove_update_or_add(socket, (readable ? Poll::In : 0)|(writable ? Poll::Out : 0))
end

ares.getaddrinfo("redirect.github.com", "https") do |cname, ai, error|
  puts "github"
  puts ai.inspect
end

ares.getaddrinfo("www.qwgeqgh.org", "qegqe") do |cname, ai, error|
  puts "error"
  puts error.inspect
end

ares.getaddrinfo("www.ruby-lang.org", "https") do |cname, ai, error|
  puts "ruby-lang"
  puts cname.inspect
  puts ai.inspect
end

ares.getaddrinfo("localhost", "ircd") do |cname, ai, error|
  puts "localhost"
  puts ai.inspect
end

while ((timeout = ares.timeout) > 0.0)
  poll.wait(timeout * 1000) do |fd|
    ares.process_fd((fd.readable?) ? fd.socket : -1, (fd.writable?) ? fd.socket : -1)
  end
end
```

Lets go through it.
Ares.new creates a new Arex context, you have to supply a function which polls on its supplied Sockets.
socket.readable? and socket.writable? return false at the same time when you don't have to poll on the socket anymore.

ares.getaddrinfo takes up to 6 arguments, the name to lookup, the service, flags, the address family, the socktype, and the protocol.
Take a look at https://c-ares.org/ares_getaddrinfo.html for more informations.


ares.timeout returns how long the current operations timeout is, once the current operations have completed 0.0 is returned.

Ares.new takes a optional Argument for options during context initialization.
The current supported options can be seen in ```mrblib/ares.rb```.
For what those options do take a look at https://c-ares.org/ares_init_options.html
Which options can be used depends on your installed c-ares library Version, calling ```Ares::Options::AVAILABLE_OPTIONS``` shows you all available ones.

There are three more functions for a Ares context, ```ares.servers_ports_csv=```, ```ares.local_ip4=``` and ```ares.local_ip6=```
ares.servers_ports_csv= excepts a string with the following formatting ip[:port][%iface], separated by commas.
Take a look at https://c-ares.org/ares_set_servers_ports_csv.html for more information.

ares.local_ip4= excepts a dotted IPv4 Address. ares.local_ip6= excepts a IPv6 Address.
It sets the local Adress from which requests are made.

Error Handling
==============
Usage errors raise exceptions, aka wrong arguments and such.

Errors while doing Name Resolution set the error variable of the passed callback, they are exceptions but aren't raised.
In the example from above the second call to getaddrinfo returns one such error.

Notes
=====
Ares Constants are mapped 1:1 to this library, when you take a look at the c-ares documentation you see constants like this ARES_AI_NUMERICSERV, they are available as Ares::AI_NUMERICSERV in this gem.