server = TCPServer.new('::', 0)
uring = IO::Uring.new
pollers =  {}
ares = Ares.new do |socket, readable, writable|
  if (readable || writable)
    if userdata = pollers[socket]
      pollers[socket] = userdata.update((readable ? IO::Uring::POLLIN : 0)|(writable ? IO::Uring::POLLOUT : 0), IO::Uring::POLL_UPDATE_EVENTS)
    else
      pollers[socket] = uring.prep_poll_multishot(socket, (readable ? IO::Uring::POLLIN : 0)|(writable ? IO::Uring::POLLOUT : 0))
    end
  else
    uring.prep_cancel(pollers[socket])
  end
end

ares.getaddrinfo(server, "www.ruby-lang.org", "https") do |cname, ai, error|
  puts "ruby-lang"
  puts cname.inspect
  puts ai.inspect
end

ares.getaddrinfo(server, "redirect.github.com", "https") do |cname, ai, error|
  puts "github"
  puts ai.inspect
end

ares.getaddrinfo(server, "www.qwgeqgh.org", "qegqe") do |cname, ai, error|
  puts "error"
  puts error.inspect
end

ares.getaddrinfo(server, "localhost", "ircd") do |cname, ai, error|
  puts "localhost"
  puts ai.inspect
end

while ((timeout = ares.timeout) > 0.0)
  uring.wait(timeout) do |userdata|
    raise userdata.errno if userdata.errno
    if userdata.type != :cancel
      ares.process_fd((userdata.readable?) ? userdata.socket : -1, (userdata.writable?) ? userdata.socket : -1)
    end
  end
end
