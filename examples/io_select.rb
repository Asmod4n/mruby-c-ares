Ares.run do |dns|
  dns.query("example.com", :A) do |timeouts, hostent, error|
    p "example.com a"
    p hostent
  end
  dns.getaddrinfo("www.ruby-lang.org", 443) do |timeouts, cname, ai, error|
    puts "ruby-lang"
    puts cname.inspect
    puts ai.inspect
  end
  dns.getaddrinfo("localhost", "https") do |timeouts, cname, ai, error|
    puts "localhost"
    puts ai.inspect
  end
  dns.query("_443._tcp.fedoraproject.org", :TLSA) do |timeouts, hostent, error|
    p "fedora"
    p hostent
  end
  dns.query("example.com", :HTTPS) do |timeouts, hostent, error|
    p "example https"
    p hostent
  end
  dns.query("example.com", :NS) do |timeouts, hostent, error|
    p "example.com aaaa"
    p hostent
  end
end
