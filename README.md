# mruby-c-ares

Async DNS client for mruby, built on [c-ares](https://c-ares.org/).

Supports `getaddrinfo`, `getnameinfo`, and arbitrary DNS record queries (A, AAAA, MX, CNAME, TLSA, HTTPS, SRV, TXT, SOA, NS, CAA, and any other type your c-ares version knows about) with full answer/authority/additional section parsing.

## Requirements

c-ares >= 1.16.0 with development headers, and a 64-bit mruby build (`MRB_INT_BIT >= 64`).

**Debian/Ubuntu:**
```
apt install libc-ares-dev
```

**macOS (Homebrew):**
```
brew install c-ares
```

**openSUSE:**
```
zypper install c-ares-devel
```

For other platforms, check your package manager for a `c-ares` package or build from source: https://github.com/c-ares/c-ares/blob/main/INSTALL.md

If none of those options work, the gem includes c-ares as a git submodule under `deps/c-ares` and will build it automatically via CMake when the system library isn't found.

## Installation

Add to your `build_config.rb`:

```ruby
MRuby::Build.new do |conf|
  # ...
  conf.gem mgem: 'mruby-c-ares'
end
```

### Dependencies

- `mruby-socket` (for `Addrinfo` and `Socket::AF_*` constants)
- `mruby-c-ext-helpers`
- `mruby-uri-parser`

## Usage

### Quick Start with `Ares.run`

`Ares.run` provides a self-contained event loop using `IO.select` — no external poller needed:

```ruby
Ares.run do |dns|
  dns.query("example.com", :A) do |timeouts, answers, extra|
    answers.each { |rr| puts "#{rr[:name]} => #{rr[:a_addr]}" }
  end

  dns.query("example.com", :AAAA) do |timeouts, answers, extra|
    answers.each { |rr| puts "#{rr[:name]} => #{rr[:aaaa_addr]}" }
  end

  dns.query("example.com", :MX) do |timeouts, answers, extra|
    answers.each { |rr| puts "pri=#{rr[:mx_preference]} host=#{rr[:mx_exchange]}" }
  end

  dns.getaddrinfo("www.ruby-lang.org", 443) do |timeouts, cnames, addrinfos, error|
    if error
      puts "Error: #{error}"
    else
      puts "CNAMEs: #{cnames.inspect}"
      addrinfos.each { |ai| puts ai.inspect }
    end
  end

  dns.getnameinfo(Socket::AF_INET, "185.199.111.153", 443) do |timeouts, name, service, error|
    puts "Reverse: #{name} / #{service}" unless error
  end
end
```

### Manual Event Loop

For integration with io\_uring, epoll, or any custom poller, create the `Ares` context directly. The block receives socket state changes — you must arrange to poll (or stop polling) each socket accordingly:

```ruby
ares = Ares.new do |socket, readable, writable|
  # readable/writable are both false when the socket should be removed
  my_poller.update(socket, readable, writable)
end

ares.getaddrinfo("example.com", "https") do |timeouts, cnames, addrinfos, error|
  puts addrinfos.inspect
end

while (timeout = ares.timeout) > 0.0
  my_poller.wait(timeout) do |fd, r, w|
    ares.process_fd(r ? fd : -1, w ? fd : -1)
  end
end
```

See `examples/io_uring.rb` for a complete io\_uring integration.

## API Reference

### `Ares.new(options = Ares::Options.new, &block) → Ares`

Creates a new resolver context.

**block** `{|socket, readable, writable| ... }` — called by c-ares whenever socket polling state changes. When both `readable` and `writable` are `false`, stop polling that socket.

**options** can be an `Ares::Options` object or a Hash with any of the following keys:

| Key                | Type    | Description |
|--------------------|---------|-------------|
| `:flags`           | Integer | Bitwise OR of `Ares::FLAG_*` constants |
| `:timeout`         | Integer | Query timeout in milliseconds |
| `:tries`           | Integer | Number of query attempts |
| `:ndots`           | Integer | Threshold for FQDN detection |
| `:domains`         | Array   | Search domain list (passed as splat to `domains_set`) |
| `:ednspsz`         | Integer | EDNS UDP payload size |
| `:resolvconf_path` | String  | Path to resolv.conf |
| `:hosts_path`      | String  | Path to hosts file |
| `:udp_max_queries` | Integer | Max queries per UDP connection |
| `:maxtimeout`      | Integer | Maximum timeout in milliseconds |
| `:qcache_max_ttl`  | Integer | Query cache max TTL (seconds) |

Available options depend on your c-ares version. Call `Ares::Options::AVAILABLE_OPTIONS` to see which are supported.

For details on what each option does: https://c-ares.org/docs/ares_init_options.html

### `Ares.run { |dns| ... } → Ares`

Convenience method that creates a resolver with `IO.select`-based polling, yields it to the block, then runs the event loop until all queries complete. No external poller required.

### `ares.query(name, type, class = :IN) { |timeouts, answers, extra_or_error| ... }`

Performs a DNS query using the c-ares dnsrec API.

- **name** — domain name to query (String)
- **type** — record type as a Symbol (`:A`, `:AAAA`, `:MX`, `:CNAME`, `:TXT`, `:SRV`, `:SOA`, `:NS`, `:CAA`, `:TLSA`, `:HTTPS`, `:SVCB`, etc.). All types known to your c-ares version are available via `Ares::RecType`.
- **class** — DNS class, defaults to `:IN`. Available classes in `Ares::DnsClass`.

**Callback arguments:**

- `timeouts` — number of timeouts that occurred during the query
- `answers` — Array of Hashes on success, `nil` on error. Each hash contains `:name`, `:type` (Symbol), `:class` (Symbol), `:ttl`, plus type-specific fields (e.g. `:a_addr`, `:aaaa_addr`, `:mx_preference`, `:mx_exchange`, `:txt_data`, `:srv_target`, etc.). Field names come from `Ares::RRFieldMap`.
- `extra_or_error` — on success, a Hash with `:authority` and `:additional` arrays (same format as answers). On error, an `Ares::Error` exception (not raised, just passed).

`search` is an alias for `query`.

### `ares.getaddrinfo(name, service, flags = 0, family = AF_UNSPEC, socktype = 0, protocol = 0) { |timeouts, cnames, addrinfos, error| ... }`

Resolves a hostname to addresses, similar to POSIX `getaddrinfo`.

- **name** — hostname to resolve (String, or nil)
- **service** — service name (String), port number (Integer), or `nil`
- **flags, family, socktype, protocol** — optional hints (see `Ares::AI_*` constants)

**Callback arguments:**

- `timeouts` — number of timeouts
- `cnames` — Array of CNAME strings, or `nil`
- `addrinfos` — Array of `Addrinfo` objects, or `nil`
- `error` — `Ares::Error` on failure, `nil` on success

### `ares.getnameinfo(af, ip_address = nil, port = 0, flags = 0) { |timeouts, name, service, error| ... }`

Reverse DNS lookup.

- **af** — address family (`Socket::AF_INET` or `Socket::AF_INET6`)
- **ip_address** — IP address string to reverse-lookup (optional)
- **port** — port number to reverse-lookup (optional)
- **flags** — bitwise OR of `Ares::NI_*` constants. `LOOKUPHOST`/`LOOKUPSERVICE` flags are set automatically based on which of ip\_address/port you provide.

**Callback arguments:**

- `timeouts` — number of timeouts
- `name` — resolved hostname (String or nil)
- `service` — resolved service name (String or nil)
- `error` — `Ares::Error` on failure, `nil` on success

### `ares.timeout(max = nil) → Float`

Returns the number of seconds until the next timeout fires. Returns `0.0` when no queries are pending. Pass `max` to clamp the returned value.

### `ares.process_fd(read_fd, write_fd)`

Notify c-ares that a socket is ready for reading/writing. Pass `-1` for a direction that isn't ready.

### `ares.process(readable_ios, writable_ios)`

Notify c-ares using arrays of IO objects (as returned by `IO.select`). Builds `fd_set`s internally.

### `ares.servers_ports_csv = "ip[:port][%iface],..."` 

Set DNS servers. See https://c-ares.org/docs/ares_set_servers_ports_csv.html

### `ares.local_ip4 = "1.2.3.4"`

Set the local IPv4 address for outgoing queries.

### `ares.local_ip6 = "::1"`

Set the local IPv6 address for outgoing queries.

## Constants

All c-ares `ARES_*` constants are mapped directly — `ARES_AI_NUMERICSERV` becomes `Ares::AI_NUMERICSERV`, `ARES_FLAG_USEVC` becomes `Ares::FLAG_USEVC`, etc.

Status codes are mapped to exception subclasses under `Ares::`. For example, `ARES_ENOTFOUND` corresponds to `Ares::ENOTFOUND < Ares::Error`.

Record types and DNS classes are available as symbol-keyed hashes:
- `Ares::RecType` — `{ A: 1, AAAA: 28, MX: 15, ... }`
- `Ares::DnsClass` — `{ IN: 1, ... }`
- `Ares::RecTypeInverse` / `Ares::DnsClassInverse` — reverse mappings (integer → symbol)

RR field names: `Ares::RRFieldMap` maps c-ares `ARES_RR_*` integer keys to symbols. OPT/SVCB parameter names: `Ares::RROptParamMap`.

## Error Handling

Usage errors (wrong argument types, missing blocks) raise exceptions immediately.

DNS resolution errors are passed to the callback as an `Ares::Error` subclass — they are **not** raised. Check the error argument in your callback:

```ruby
ares.query("nonexistent.invalid", :A) do |timeouts, answers, extra_or_error|
  if answers.nil?
    puts "DNS error: #{extra_or_error.message}"  # => "Domain name not found"
    puts extra_or_error.class                     # => Ares::ENOTFOUND
  end
end
```

## License

MIT — see [LICENSE](LICENSE).
