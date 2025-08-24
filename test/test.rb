
# Helper to wrap Ares::query with Poll waiting
# Returns [records_array, error_or_nil]
def query_with_poll(domain, type)
  poll = Poll.new
  ares = Ares.new do |sock, r, w|
    poll.remove_update_or_add(
      sock,
      (r ? Poll::In : 0) | (w ? Poll::Out : 0)
    )
  end

  recs = nil
  err  = nil
  ares.query(domain, type) do |_, records, error|
    recs = records
    err  = error
  end

  # drive the event loop until query completes
  while (timeout = ares.timeout) > 0.0
    poll.wait((timeout * 1000)) do |fd|
      ares.process_fd(
        fd.readable? ? fd.socket : -1,
        fd.writable? ? fd.socket : -1
      )
    end
  end

  [recs, err]
end

# === getaddrinfo valid host ===
assert("Ares getaddrinfo valid host") do
  poll = Poll.new
  ares = Ares.new do |sock, r, w|
    poll.remove_update_or_add(
      sock,
      (r ? Poll::In : 0) | (w ? Poll::Out : 0)
    )
  end

  ai  = nil
  err = nil
  ares.getaddrinfo("localhost", "http") { |_, _, result, e| ai = result; err = e }

  while (timeout = ares.timeout) > 0.0
    poll.wait((timeout * 1000)) do |fd|
      ares.process_fd(
        fd.readable? ? fd.socket : -1,
        fd.writable? ? fd.socket : -1
      )
    end
  end

  assert_true ai.is_a?(Array) && !ai.empty?,
              "expected localhost → [addrs], got #{ai.inspect} / #{err.inspect}"
end

# === getaddrinfo invalid host ===
assert("Ares getaddrinfo invalid host") do
  poll = Poll.new
  ares = Ares.new do |sock, r, w|
    poll.remove_update_or_add(
      sock,
      (r ? Poll::In : 0) | (w ? Poll::Out : 0)
    )
  end

  err = nil
  ares.getaddrinfo("nonexistent.domain", "http") { |_, _, _, e| err = e }

  while (timeout = ares.timeout) > 0.0
    poll.wait((ares.timeout * 1000)) do |fd|
      ares.process_fd(
        fd.readable? ? fd.socket : -1,
        fd.writable? ? fd.socket : -1
      )
    end
  end

  assert_true err.is_a?(Ares::ENOTFOUND),
              "expected ENOTFOUND for nonexistent.domain, got #{err.inspect}"
end

# === getnameinfo reverse lookup ===
assert("Ares getnameinfo reverse lookup") do
  poll = Poll.new
  ares = Ares.new do |sock, r, w|
    poll.remove_update_or_add(
      sock,
      (r ? Poll::In : 0) | (w ? Poll::Out : 0)
    )
  end

  hostname = nil
  err      = nil
  ares.getnameinfo(Socket::AF_INET, "127.0.0.1", 80) do |_, name, _, e|
    hostname = name
    err      = e
  end

  while (timeout = ares.timeout) > 0.0
    poll.wait((timeout * 1000)) do |fd|
      ares.process_fd(
        fd.readable? ? fd.socket : -1,
        fd.writable? ? fd.socket : -1
      )
    end
  end

  ok = (hostname == "localhost" || hostname == "ip6-localhost")
  assert_true ok,
              "expected reverse lookup localhost/ip6-localhost, got #{hostname.inspect} / #{err.inspect}"
end

# === RR type tests ===
RR_QUERIES = {
  A:     "example.com",                         # IPv4 address
  AAAA:  "ipv6.google.com",                     # IPv6 address
  CNAME: "www.github.com",                      # Canonical name
  NS:    "example.com",                         # Name servers
  SOA:   "example.com",                         # Start of authority
  PTR:   "8.8.8.8.in-addr.arpa",                 # Reverse lookup
  MX:    "gmail.com",                            # Mail exchangers
  TXT:   "example.com",                          # Text records
  SRV:   "_xmpp-server._tcp.jabber.org",         # Stable SRV
  NAPTR: "sip2sip.info",                         # SIP NAPTR
  HTTPS: "cloudflare.com",                       # HTTPS RR
  CAA:   "sslmate.com"                           # Publishes CAA
}

RR_QUERIES.each do |rtype, domain|
  assert("Ares query #{rtype} record") do
    records, err = query_with_poll(domain, rtype)

    assert_true !records.empty?,
                "#{rtype} #{domain} → records: #{records.inspect}, error: #{err.inspect}"
  end
end

# === invalid MX query ===
assert("Ares query invalid MX") do
  poll = Poll.new
  ares = Ares.new do |sock, r, w|
    poll.remove_update_or_add(
      sock,
      (r ? Poll::In : 0) | (w ? Poll::Out : 0)
    )
  end

  err = nil
  ares.query("nonexistent.domain", :MX) { |_, _, e| err = e }

  while (timeout = ares.timeout) > 0.0
    poll.wait((ares.timeout * 1000)) do |fd|
      ares.process_fd(
        fd.readable? ? fd.socket : -1,
        fd.writable? ? fd.socket : -1
      )
    end
  end

  assert_true err.is_a?(Ares::ENOTFOUND),
              "expected ENOTFOUND for nonexistent.mx, got #{err.inspect}"
end
