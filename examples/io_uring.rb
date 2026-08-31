uring = IO::Uring.new
pollers =  {}
ares = Ares.new do |socket, readable, writable|
  if (readable || writable)
    if operation = pollers[socket]
      pollers[socket] = uring.prep_poll_update(operation, (readable ? POLLIN : 0)|(writable ? POLLOUT : 0), POLL_UPDATE_EVENTS)
    else
      pollers[socket] = uring.prep_poll_multishot(socket, (readable ? POLLIN : 0)|(writable ? POLLOUT : 0))
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

ares.getaddrinfo("www.qwgeqgh.org", "qegqe") do |timeouts, cname, ai, error|
  puts "error"
  puts error.inspect
end

ares.getaddrinfo("localhost", "https") do |timeouts, cname, ai, error|
  puts "localhost"
  puts ai.inspect
end

ares.getnameinfo(Socket::AF_INET, "185.199.111.153", 443) do |timeouts, name, service, error|
  puts "ruby-lang-reverse"
  puts "name: #{name} service: #{service}"
end

ares.search("heise.de", :AAAA) do |timeouts, hostent, error|
  puts "heise AAAA"
  puts hostent.inspect
end

while ares.active_queries > 0
  # wait(wait_nr, timeout): the count comes FIRST and the seconds second.
  # ares.timeout is a Float of seconds, so it belongs in the second slot -
  # passed as the first it becomes a completion count, and the ring then
  # either returns EAGAIN (count 0, under a second) or waits forever
  # (count > 0, no timeout).
  ready = uring.wait(1, ares.timeout) do |operation|
    raise operation.errno if operation.errno
    if operation.type != :cancel
      ares.process_fd((operation.readable?) ? operation.sock : -1, (operation.writable?) ? operation.sock : -1)
      # io_uring_prep_poll_multishot(3): a CQE without IORING_CQE_F_MORE is
      # the end of that registration, and "the application should not expect
      # further CQEs from the original request and must reissue a new one if
      # it still wishes to get notifications on this file descriptor".
      # process_fd ran first, so a socket c-ares has dropped is already out
      # of pollers, and one whose interest moved holds a different operation.
      unless operation.more?
        if pollers[operation.sock] == operation
          pollers[operation.sock] = uring.prep_poll_multishot(operation.sock, operation.poll_mask)
        end
      end
    end
  end
  # ETIME, no socket was ready. c-ares still has to hear that the time
  # passed, or its retries and query timeouts never run - the same reason
  # io_select.rb processes empty fd sets when IO.select returns nil.
  ares.process_fd(-1, -1) unless ready
end
