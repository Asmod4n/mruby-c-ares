class Ares
  def self.new(options = Ares::Options.new, &block)
    case options
    when Ares::Options
      super(options, &block)
    when Enumerable
      opts = Ares::Options.new
      options.each do |key, value|
        case key
        when :flags
          opts.flags = value
        when :timeout
          opts.timeout = value
        when :tries
          opts.tries = value
        when :ndots
          opts.ndots = value
        when :domains
          opts.domains_set(*value)
        when :ednspsz
          opts.ednspsz = value
        when :resolvconf_path
          opts.resolvconf_path = value
        when :hosts_path
          opts.hosts_path = value
        when :udp_max_queries
          opts.udp_max_queries = value
        when :maxtimeout
          opts.maxtimeout = value
        when :qcache_max_ttl
          opts.qcache_max_ttl = value
        else
          raise ArgumentError, "unknown opt"
        end
      end
      super(opts, &block)
    else
      raise ArgumentError, "unknown options"
    end
  end
end

class Ares
  # Runs a self-contained IO.select event loop around a resolver created just
  # for this call, so state from one run (pollers, half-finished queries, an
  # exception raised inside a callback) can never leak into the next one.
  def self.run(options = Ares::Options.new, &block)
    raise ArgumentError, "no block given" unless block

    pollers       = {}   # fd => Socket (one wrapper per c-ares socket)
    read_pollers  = {}
    write_pollers = {}

    # c-ares owns its sockets and closes them itself, so the wrappers must
    # never close the fds on GC (autoclose = false) — by then the OS may
    # have handed the same fd number to someone else.
    ares = Ares.new(options) do |socket, readable, writable|
      if readable || writable
        sock = pollers[socket] ||= begin
          s = Socket.for_fd(socket)
          s.autoclose = false
          s
        end
        readable ? read_pollers[socket] = sock : read_pollers.delete(socket)
        writable ? write_pollers[socket] = sock : write_pollers.delete(socket)
      else
        pollers.delete(socket)
        read_pollers.delete(socket)
        write_pollers.delete(socket)
      end
    end

    block.call(ares)

    while ares.active_queries > 0
      # IO.select returns nil on timeout; processing with empty fd sets is
      # exactly what lets c-ares handle retries and query timeouts.
      readable, writable = IO.select(read_pollers.values, write_pollers.values, nil, ares.timeout)
      ares.process(readable || [], writable || [])
    end

    self
  end
end
