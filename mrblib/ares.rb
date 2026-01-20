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
  @read_pollers  = {}   # fd => IO
  @write_pollers = {}   # fd => IO

  @ares = Ares.new do |socket, readable, writable|
    if readable
      @read_pollers[socket] ||= IO.for_fd(socket, "r")
    else
      @read_pollers.delete(socket)
    end

    if writable
      @write_pollers[socket] ||= IO.for_fd(socket, "w")
    else
      @write_pollers.delete(socket)
    end
  end

  def self.run(&block)
    raise ArgumentError, "no block given" unless block

    block.call(@ares)

    loop do
      timeout = @ares.timeout
      break if timeout <= 0.0

      readable, writable = IO.select(@read_pollers.values, @write_pollers.values, nil, timeout)
      readable ||= []
      writable ||= []

      # Build tiny readiness tables (fd => IO)
      read_ready  = {}
      write_ready = {}

      readable.each  { |io| read_ready[io.fileno]  = io }
      writable.each  { |io| write_ready[io.fileno] = io }

      # Process each fd once with combined readiness
      (@read_pollers.keys | @write_pollers.keys).each do |fd|
        @ares.process_fd(
          read_ready[fd]  || -1,
          write_ready[fd] || -1
        )
      end
    end

    self
  end
end
