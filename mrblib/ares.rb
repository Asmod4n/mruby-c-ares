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
