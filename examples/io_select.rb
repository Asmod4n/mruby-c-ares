Ares.run do |dns|
  dns.query("example.com", :A) do |timeouts, hostent, error|
    p "example.com"
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
end
