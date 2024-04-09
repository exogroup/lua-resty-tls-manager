local tls_manager = {}

-- preload modules
function tls_manager.preload_modules()
  require "resty.tls_manager.strategy_files"
  require "resty.tls_manager.strategy_consul"
end

function tls_manager.new(args)
  -- actual object
  local self = {}

  -- when no args are passed
  self.args = args or {}

  -- load the nginx ssl library
  self.ssl = require "ngx.ssl"

  -- configure the shared cache
  self.cache = ngx.shared.tls
  if type(self.cache) ~= "table" then
    error("missing 'tls' shared dictionary")
    return
  end

  -- set cache TTL (default: 3600)
  self.cache_ttl = args.cache_ttl or 3600

  -- returns the strategy object
  function self.strategy()
    local name = self.args.strategy or "files"
    local o = "resty.tls_manager.strategy_" .. name
    if not pcall(require, o) then
      error("strategy not found or syntax error in: " .. name)
    end
    -- instantiate and returns the strategy object
    -- passing the object constructor arguments
    return require(o).new(self.args)
  end

  -- retrieves the domain name out of the
  -- SSL server name provided by nginx
  function self.get_ssl_domain()
    local server_name = self.ssl.server_name()
    return server_name:match("([%w-]+%.[%w-]+)$")
  end

  -- retrieves the certificate for a domain
  -- stored in shared cache. Returns nil when
  -- the certificate is not found
  function self.get_cached_certificate_file(domain)
    return self.cache:get(domain .. "_crt")
  end

  -- retrieves the certificate key for a domain
  -- stored in shared cache. Returns nil when
  -- the keys is not found
  function self.get_cached_certificate_key(domain)
    return self.cache:get(domain .. "_key")
  end

  -- stores the certificate for a domain in the
  -- shared cache for later retrieval
  function self.cache_certificate_file(domain, data)
    return self.cache:set(domain .. "_crt", data, self.cache_ttl)
  end

  -- stores the certificate key for a domain in the
  -- shared cache for later retrieval
  function self.cache_certificate_key(domain, data)
    return self.cache:set(domain .. "_key", data, self.cache_ttl)
  end

  -- stores both certificate file and key in the
  -- shared cache for later retrieval
  function self.cache_certificate(domain, cert, key)
    self.cache_certificate_file(domain, cert)
    self.cache_certificate_key(domain, key)
  end

  -- retrieve both certificate file and key from
  -- the shared cache
  function self.get_cached_certificate(domain)
    return self.get_cached_certificate_file(domain),
           self.get_cached_certificate_key(domain)
  end

  function self.get_certificate()
    -- retrieves the domain
    local domain = self.get_ssl_domain()
    if domain == "" then
      -- unable to parse the domain
      return
    end
    -- attempt reading data from cache first
    local cert, key = self.get_cached_certificate(domain)
    if cert == nil or key == nil then
      -- certificate not in cache, retrieving from origin
      local strategy = self.strategy()
      print("certificate not found in cache for domain: " .. domain)
      print("using strategy [" .. strategy.name() .. "] to fetch certificate data")
      cert, key = strategy.retrieve(domain)
      if cert == nil or key == nil then
        error("cannot retrieve certificate data for domain: " .. domain)
        return
      end
      -- save certificate data in cache
      print("storing certificate for domain ".. domain .." in shared cache")
      self.cache_certificate(domain, cert, key)
    else
      -- certificate loaded from cache
      print('certificate retrieved from cache for domain: ' .. domain)
    end
    return cert, key
  end

  -- function to be called within ssl_certificate_by_lua_block
  -- this is where all the magic happens
  function self.handle()
   print("handling SSL handshake for server name: " .. self.ssl.server_name())
   local cert, key = self.get_certificate()
    if cert == nil or key == nil then
      error("something went wrong while attempting to fetch the certificate data")
      return
    end
    self.ssl.set_cert(self.ssl.parse_pem_cert(cert))
    self.ssl.set_priv_key(self.ssl.parse_pem_priv_key(key))
    print("TLS certificate applied successfully")
  end

  -- returns the object instance
  return self
end

return tls_manager
