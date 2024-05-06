server = TCPServer.new('::', 0)
server._setnonblock(true)
poll = Poll.new
ares = Ares.new do |socket|
  poll.remove_update_or_add(socket, (socket.readable? ? Poll::In : 0)|(socket.writable? ? Poll::Out : 0))
end

ares.getaddrinfo(server, "redirect.github.com", "https") do |cname, ai, error|
  puts "github"
  puts ai.inspect
  puts error.inspect
end

ares.getaddrinfo(server, "www.qwgeqgh.org", "qegqe") do |cname, ai, error|
  puts "error"
  puts error.inspect
end

ares.getaddrinfo(server, "www.ruby-lang.org", "https") do |cname, ai, error|
  puts "ruby-lang"
  puts cname.inspect
  puts ai.inspect
  puts error.inspect
end

ares.getaddrinfo(server, "localhost", "ircd") do |cname, ai, error|
  puts "localhost"
  puts ai.inspect
  puts error.inspect
end

while ((timeout = ares.timeout) > 0.0)
  poll.wait(timeout * 1000) do |fd|
    ares.process_fd((fd.readable?) ? fd.socket : -1, (fd.writable?) ? fd.socket : -1)
  end
end
