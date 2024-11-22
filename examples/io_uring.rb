uring = IO::Uring.new
pollers =  {}
ares = Ares.new do |socket, readable, writable|
  if (readable || writable)
    if operation = pollers[socket]
      pollers[socket] = uring.prep_poll_update(operation, (readable ? IO::Uring::POLLIN : 0)|(writable ? IO::Uring::POLLOUT : 0), IO::Uring::POLL_UPDATE_EVENTS)
    else
      pollers[socket] = uring.prep_poll_multishot(socket, (readable ? IO::Uring::POLLIN : 0)|(writable ? IO::Uring::POLLOUT : 0))
    end
  else
    uring.prep_cancel(pollers[socket])
    pollers.delete(socket)
  end
end

ares.getaddrinfo("www.ruby-lang.org", 443) do |timeouts, cname, ai, error|
  puts "ruby-lang"
  puts cname.inspect
  puts ai.inspect
end

ares.getaddrinfo("redirect.github.com", "https") do |timeouts, cname, ai, error|
  puts "github"
  puts ai.inspect
end

ares.getaddrinfo("www.qwgeqgh.org", "qegqe") do |timeouts, cname, ai, error|
  puts "error"
  puts error.inspect
end

ares.getaddrinfo("localhost", "ircd") do |timeouts, cname, ai, error|
  puts "localhost"
  puts ai.inspect
end

ares.getnameinfo(Socket::AF_INET, "185.199.111.153", 443) do |timeouts, name, service, error|
  puts "ruby-lang-reverse"
  puts "name: #{name} service: #{service}"
end

ares.search("github.com", :MX) do |timeouts, hostent, error|
  puts "github MX"
  puts hostent.inspect
end

while ((timeout = ares.timeout) > 0.0)
  uring.wait(timeout) do |operation|
    raise operation.errno if operation.errno
    if operation.type != :cancel
      ares.process_fd((operation.readable?) ? operation.sock : -1, (operation.writable?) ? operation.sock : -1)
    end
  end
end
