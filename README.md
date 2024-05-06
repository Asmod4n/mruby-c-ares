# mruby-c-ares
Async DNS for mruby

Requirements
============
You need to have the c-ares library with development headers installed for your target.

Installation
============
create a build_config.rb file and add gem mgem: 'mruby-c-ares' to it

Usage examples
==============

Currently only getaddrinfo is implemented, aka resolve a hostname to a IPv(4|6) Address, if you need more let me know!

requires 'mruby-poll'
```ruby
poll = Poll.new
server = TCPServer.new('::', 0)
server._setnonblock(true)
ares = Ares.new do |socket|
  poll.remove_update_or_add(socket, (socket.readable? ? Poll::In : 0)|(socket.writable? ? Poll::Out : 0))
end

ares.getaddrinfo(server, "www.ruby-lang.org", "https") do |cname, ai, error|
  puts cname.inspect
  puts ai.inspect
  puts error.inspect
end

ares.getaddrinfo(server, "redirect.github.com", "https") do |cname, ai, error|
  puts cname.inspect
  puts ai.inspect
  puts error.inspect
end

ares.getaddrinfo(server, "www.qwgeqgh.org", "qegqe") do |cname, ai, error|
  puts cname.inspect
  puts ai.inspect
  puts error.inspect
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

ares.getaddrinfo expects a socket as it's first parameter optionally, it checks what type of socket is passed and calls a callback with relevant information for that type of socket, you can immediately connect to every entry of the returned Addrinfo array, you only get replies the socket you supplied can handle.

ares.timeout returns how long the current operations timeout is, once the current operations have completed 0.0 is returned.
ares.timeout returns a mruby float with seconds and miliseconds as the remainder.

Ares.new takes a optional Argument, the Argument are options for context initialization.
The current supported options can be seen in ```mrblib/ares.rb```.

There are three more functions for a Ares context, servers_ports_csv=, local_ip4= and local_ip6=
ares.servers_ports_csv= excepts a string with the following formatting ip[:port][%iface].
Take a look at https://c-ares.org/ares_set_servers_ports_csv.html for more information.

ares.local_ip4= excepts a dotted IPv4 Address. ares.local_ip6= excepts a IPv6 Address.

For flags which can be set in Ares::Options, take a look at https://c-ares.org/ares_init_options.html
every flag is covered, you can get them via Ares::FLAG_EDNS for example.

Error Handling
==============
Usage errors raise exceptions, aka wrong arguments and such.

Errors while doing Name Resolution set the error variable of the passed callback, they are exceptions but aren't raised.
In the example from above the third call to getaddrinfo returns one such error.