assert("Ares getaddrinfo valid host") do
  poll = Poll.new
  ares = Ares.new do |socket, readable, writable|
    poll.remove_update_or_add(socket, (readable ? Poll::In : 0) | (writable ? Poll::Out : 0))
  end

  result = nil
  ares.getaddrinfo("localhost", "http") do |timeouts, cname, ai, error|
    result = ai
  end

  # wait for callback
  while result.nil?
    poll.wait(ares.timeout*1000) {|fd| ares.process_fd(fd.readable? ? fd.socket : -1, fd.writable? ? fd.socket : -1) }
  end

  assert_true result.any?, "localhost resolved"
end

assert("Ares getaddrinfo invalid host") do
  poll = Poll.new
  ares = Ares.new {|socket, r, w| poll.remove_update_or_add(socket, (r ? Poll::In : 0)|(w ? Poll::Out : 0)) }

  error = nil
  ares.getaddrinfo("nonexistent.domain", "http") do |timeouts, cname, ai, err|
    error = err
  end

  while error.nil?
    poll.wait(ares.timeout*1000) {|fd| ares.process_fd(fd.readable? ? fd.socket : -1, fd.writable? ? fd.socket : -1)}
  end

  assert_true error.is_a?(Ares::ENOTFOUND), "nonexistent domain returned ENOTFOUND"
end

assert("Ares getnameinfo reverse lookup") do
  poll = Poll.new
  ares = Ares.new {|socket, r, w| poll.remove_update_or_add(socket, (r ? Poll::In : 0)|(w ? Poll::Out : 0)) }

  result = nil
  ares.getnameinfo(Socket::AF_INET, "127.0.0.1", 80) do |timeouts, name, service, error|
    result = name
  end

  while result.nil?
    poll.wait(ares.timeout*1000) {|fd| ares.process_fd(fd.readable? ? fd.socket : -1, fd.writable? ? fd.socket : -1)}
  end

  assert_true result == "localhost" || result == "ip6-localhost", "reverse lookup returned #{result}"
end

assert("Ares query MX record") do
  poll = Poll.new
  ares = Ares.new {|socket, r, w| poll.remove_update_or_add(socket, (r ? Poll::In : 0)|(w ? Poll::Out : 0)) }

  mx_records = nil
  ares.query("google.com", :MX) do |timeouts, hostent, error|
    mx_records = hostent
  end

  while mx_records.nil?
    poll.wait(ares.timeout*1000) {|fd| ares.process_fd(fd.readable? ? fd.socket : -1, fd.writable? ? fd.socket : -1)}
  end

  assert_true mx_records.any?, "MX records for google.com retrieved"
end
