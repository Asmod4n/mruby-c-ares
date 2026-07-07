assert('Ares::Options defaults') do
  opts = Ares::Options.new
  assert_kind_of(Ares::Options, opts)
  assert_kind_of(Array, Ares::Options::AVAILABLE_OPTIONS)
end

assert('Ares::Options accessors round-trip') do
  opts = Ares::Options.new

  if Ares::Options::AVAILABLE_OPTIONS.include?(:flags)
    opts.flags = Ares::FLAG_USEVC
    assert_equal(Ares::FLAG_USEVC, opts.flags)
  end

  if Ares::Options::AVAILABLE_OPTIONS.include?(:timeout)
    opts.timeout = 5000
    assert_equal(5000, opts.timeout)
  end

  if Ares::Options::AVAILABLE_OPTIONS.include?(:tries)
    opts.tries = 3
    assert_equal(3, opts.tries)
  end

  if Ares::Options::AVAILABLE_OPTIONS.include?(:ndots)
    opts.ndots = 2
    assert_equal(2, opts.ndots)
  end

  if Ares::Options::AVAILABLE_OPTIONS.include?(:ednspsz)
    opts.ednspsz = 1280
    assert_equal(1280, opts.ednspsz)
  end

  if Ares::Options::AVAILABLE_OPTIONS.include?(:udp_max_queries)
    opts.udp_max_queries = 4
    assert_equal(4, opts.udp_max_queries)
  end

  if Ares::Options::AVAILABLE_OPTIONS.include?(:maxtimeout)
    opts.maxtimeout = 10_000
    assert_equal(10_000, opts.maxtimeout)
  end

  if Ares::Options::AVAILABLE_OPTIONS.include?(:qcache_max_ttl)
    opts.qcache_max_ttl = 60
    assert_equal(60, opts.qcache_max_ttl)
  end
end

assert('Ares::Options#domains_set and #domains') do
  opts = Ares::Options.new
  if Ares::Options::AVAILABLE_OPTIONS.include?(:domains)
    opts.domains_set('example.com', 'example.org')
    assert_equal(['example.com', 'example.org'], opts.domains)
    assert_true(opts.domains.frozen?)
  end
end

assert('Ares::Options#resolvconf_path= and #hosts_path=') do
  opts = Ares::Options.new
  if Ares::Options::AVAILABLE_OPTIONS.include?(:resolvconf_path)
    opts.resolvconf_path = '/etc/resolv.conf'
    assert_equal('/etc/resolv.conf', opts.resolvconf_path)
  end

  if Ares::Options::AVAILABLE_OPTIONS.include?(:hosts_path)
    opts.hosts_path = '/etc/hosts'
    assert_equal('/etc/hosts', opts.hosts_path)
  end
end

assert('Ares.new requires a block') do
  assert_raise(ArgumentError) { Ares.new }
end

assert('Ares.new with an Ares::Options object') do
  ares = Ares.new(Ares::Options.new) { |_socket, _readable, _writable| }
  assert_kind_of(Ares, ares)
end

assert('Ares.new with a Hash of options') do
  ares = Ares.new(timeout: 1000, tries: 2) { |_socket, _readable, _writable| }
  assert_kind_of(Ares, ares)
end

assert('Ares.new with an unknown Hash option raises ArgumentError') do
  assert_raise(ArgumentError) do
    Ares.new(bogus_option: 1) { |_socket, _readable, _writable| }
  end
end

assert('Ares.new with an unsupported options type raises ArgumentError') do
  assert_raise(ArgumentError) do
    Ares.new(42) { |_socket, _readable, _writable| }
  end
end

assert('Ares#timeout returns a Float and is 0.0 when idle') do
  ares = Ares.new { |_socket, _readable, _writable| }
  assert_kind_of(Float, ares.timeout)
  assert_equal(0.0, ares.timeout)
end

assert('Ares#getaddrinfo requires a block') do
  ares = Ares.new { |_socket, _readable, _writable| }
  assert_raise(ArgumentError) { ares.getaddrinfo('example.com', 443) }
end

assert('Ares#getnameinfo rejects an invalid address family') do
  ares = Ares.new { |_socket, _readable, _writable| }
  assert_raise(ArgumentError) { ares.getnameinfo(-1) { |*_args| } }
end

assert('Ares#query requires a block') do
  ares = Ares.new { |_socket, _readable, _writable| }
  assert_raise(ArgumentError) { ares.query('example.com', :A) }
end

assert('Ares#query rejects an unknown record type') do
  ares = Ares.new { |_socket, _readable, _writable| }
  assert_raise(ArgumentError) { ares.query('example.com', :NOT_A_REAL_TYPE) { |*_args| } }
end

assert('Ares#search is an alias for Ares#query') do
  ares = Ares.new { |_socket, _readable, _writable| }
  assert_true(ares.respond_to?(:search))
  assert_raise(ArgumentError) { ares.search('example.com', :A) }
  assert_raise(ArgumentError) { ares.search('example.com', :NOT_A_REAL_TYPE) { |*_args| } }
end

assert('Ares::RecType and Ares::DnsClass are populated') do
  assert_kind_of(Hash, Ares::RecType)
  assert_kind_of(Hash, Ares::DnsClass)

  %i[A AAAA MX CNAME TXT SRV SOA NS CAA].each do |type|
    assert_kind_of(Integer, Ares::RecType[type])
  end

  assert_kind_of(Integer, Ares::DnsClass[:IN])
end

assert('Ares::RecTypeInverse and Ares::DnsClassInverse round-trip') do
  # Not necessarily a bijection: c-ares keeps deprecated aliases (e.g. the
  # ARES_CLASS_HESOID typo alongside ARES_CLASS_HESIOD) mapping to the same
  # integer, so only the round trip through the integer is guaranteed.
  Ares::RecType.each do |_sym, int|
    assert_equal(int, Ares::RecType[Ares::RecTypeInverse[int]])
  end

  Ares::DnsClass.each do |_sym, int|
    assert_equal(int, Ares::DnsClass[Ares::DnsClassInverse[int]])
  end
end

assert('Ares::RRFieldMap is populated') do
  assert_kind_of(Hash, Ares::RRFieldMap)
  assert_true(Ares::RRFieldMap.size > 0)
end

assert('Ares error classes derive from Ares::Error') do
  assert_kind_of(Class, Ares::Error)
  assert_kind_of(StandardError, Ares::Error.new('x'))
  assert_kind_of(Class, Ares::ENOTFOUND)
  assert_kind_of(Ares::Error, Ares::ENOTFOUND.new('x'))
end

assert('Ares.run requires a block') do
  assert_raise(ArgumentError) { Ares.run }
end

assert('Ares.run yields an Ares instance and returns Ares') do
  yielded = nil
  result = Ares.run { |dns| yielded = dns }
  assert_kind_of(Ares, yielded)
  assert_equal(Ares, result)
end

# The tests below run a tiny hand-rolled DNS server on a random local UDP
# port and point an Ares instance at it via servers_ports_csv, instead of
# depending on real internet connectivity. It only understands enough of
# the wire format to mirror the query's ID and question section back with
# a canned answer (or NXDOMAIN), which is enough to exercise c-ares'
# actual send/receive/parse path end-to-end without any external server.

def dns_response_bytes(query_bytes, ip)
  qd_end = 12
  loop do
    len = query_bytes[qd_end]
    break if len.nil?
    if len == 0
      qd_end += 1
      break
    end
    qd_end += 1 + len
  end
  question = query_bytes[12...(qd_end + 4)]
  id = query_bytes[0, 2]

  if ip
    flags = [0x81, 0x80]
    ancount = [0x00, 0x01]
    answer = [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04] +
             ip.split('.').map(&:to_i)
  else
    flags = [0x81, 0x83] # RCODE 3: NXDOMAIN
    ancount = [0x00, 0x00]
    answer = []
  end

  header = id + flags + [0x00, 0x01] + ancount + [0x00, 0x00, 0x00, 0x00]
  (header + question + answer).pack('C*')
end

def with_fixture_dns_server(response_ip)
  server = UDPSocket.new
  server.bind('127.0.0.1', 0)
  port = server.addr[1]

  read_pollers = {}
  write_pollers = {}
  ares = Ares.new do |socket, readable, writable|
    if readable
      read_pollers[socket] ||= IO.for_fd(socket, 'r')
    else
      read_pollers.delete(socket)
    end
    if writable
      write_pollers[socket] ||= IO.for_fd(socket, 'w')
    else
      write_pollers.delete(socket)
    end
  end
  ares.servers_ports_csv("127.0.0.1:#{port}")

  yield ares

  loop do
    timeout = ares.timeout
    break if timeout <= 0.0

    readables, writables = IO.select(read_pollers.values + [server], write_pollers.values, nil, timeout)
    readables ||= []
    fixture_ready = readables.include?(server)
    readables = readables - [server]

    if fixture_ready
      data, addrinfo = server.recvfrom(512)
      response = dns_response_bytes(data.bytes, response_ip)
      server.send(response, 0, addrinfo[3], addrinfo[1])
    end

    ares.process(readables, writables)
  end
ensure
  server.close
end

assert('Ares#query resolves an A record via a local fixture DNS server') do
  answers = nil
  extra = nil
  with_fixture_dns_server('203.0.113.42') do |ares|
    ares.query('fixture.mruby-c-ares.test', :A) do |_timeouts, ans, extra_or_error|
      answers = ans
      extra = extra_or_error
    end
  end

  assert_kind_of(Array, answers)
  assert_equal(1, answers.size)
  assert_equal('203.0.113.42', answers.first[:a_addr])
  assert_kind_of(Hash, extra)
  assert_equal([], extra[:authority])
  assert_equal([], extra[:additional])
end

assert('Ares#query reports ENOTFOUND via a local fixture DNS server') do
  answers = :unset
  error = nil
  with_fixture_dns_server(nil) do |ares|
    ares.query('nope.mruby-c-ares.test', :A) do |_timeouts, ans, extra_or_error|
      answers = ans
      error = extra_or_error
    end
  end

  assert_nil(answers)
  assert_kind_of(Ares::ENOTFOUND, error)
end

assert('Ares#getaddrinfo resolves via a local fixture DNS server') do
  addrinfos = nil
  error = nil
  with_fixture_dns_server('203.0.113.42') do |ares|
    ares.getaddrinfo('fixture.mruby-c-ares.test', 80, 0, Socket::AF_INET) do |_timeouts, _cnames, ai, err|
      addrinfos = ai
      error = err
    end
  end

  assert_nil(error)
  assert_kind_of(Array, addrinfos)
  assert_equal(1, addrinfos.size)
  assert_equal('203.0.113.42', addrinfos.first.ip_address)
end

# Exceptions raised inside a c-ares callback block must not unwind through
# c-ares' plain C stack frames. The C shim parks them in mrb->exc instead,
# and mruby re-raises them as soon as control returns from process/query/
# getaddrinfo, so they surface as perfectly ordinary Ruby exceptions.

assert('Ares#query raising inside the callback surfaces as a Ruby exception') do
  assert_raise(RuntimeError) do
    with_fixture_dns_server('203.0.113.42') do |ares|
      ares.query('raise.mruby-c-ares.test', :A) do |_timeouts, _answers, _extra_or_error|
        raise 'boom from query callback'
      end
    end
  end

  # No corrupted global state: an unrelated query still succeeds afterwards.
  answers = nil
  with_fixture_dns_server('203.0.113.42') do |ares|
    ares.query('after-raise.mruby-c-ares.test', :A) do |_timeouts, ans, _extra_or_error|
      answers = ans
    end
  end
  assert_kind_of(Array, answers)
  assert_equal(1, answers.size)
  assert_equal('203.0.113.42', answers.first[:a_addr])
end

assert('Ares#getaddrinfo raising inside the callback surfaces as a Ruby exception') do
  assert_raise(RuntimeError) do
    with_fixture_dns_server('203.0.113.42') do |ares|
      ares.getaddrinfo('raise.mruby-c-ares.test', 80, 0, Socket::AF_INET) do |_timeouts, _cnames, _ai, _err|
        raise 'boom from getaddrinfo callback'
      end
    end
  end

  # No corrupted global state: an unrelated lookup still succeeds afterwards.
  addrinfos = nil
  with_fixture_dns_server('203.0.113.42') do |ares|
    ares.getaddrinfo('after-raise.mruby-c-ares.test', 80, 0, Socket::AF_INET) do |_timeouts, _cnames, ai, _err|
      addrinfos = ai
    end
  end
  assert_kind_of(Array, addrinfos)
  assert_equal(1, addrinfos.size)
  assert_equal('203.0.113.42', addrinfos.first.ip_address)
end
