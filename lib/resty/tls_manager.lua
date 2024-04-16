local tls_manager = {}

-- preload modules
function tls_manager.preload_modules()
  require "resty.tls_manager.cache"
  require "resty.tls_manager.strategy.files"
  require "resty.tls_manager.strategy.consul"
end

function tls_manager.new(args)
  -- actual object
  local self = {}

  -- when no args are passed
  self.args = args or {}

  -- load the nginx ssl library
  self.ssl = require "ngx.ssl"

  -- configure the shared cache
  self.cache = require("resty.tls_manager.cache").new(args.cache_name, args.cache_ttl)
  if self.cache == nil then
    ngx.log(ngx.ERR, "unable to initialize the shared cache")
    return
  end

  -- returns the strategy object
  function self.strategy()
    local name = self.args.strategy or "files"
    local prefix = self.args.strategy_prefix or "resty.tls_manager.strategy"
    local o = prefix .. "." .. name
    if not pcall(require, o) then
      ngx.log(ngx.ERR, "strategy not found or syntax error in: " .. name ..", prefix: ".. prefix)
    end
    -- instantiate and returns the strategy object
    -- passing the object constructor arguments
    return require(o).new(self.args)
  end

  -- retrieves the domain name out of the
  -- SSL server name provided by nginx
  function self.get_ssl_domain()
    local server_name = self.ssl.server_name()
    local n = 0
    for i = 1, #server_name do
      if server_name:sub(i, i) == '.' then
        n = n + 1
      end
    end
    if n == 0 then
      return nil
    elseif n == 1 then
      return server_name
    else
      -- retrieve the position of the first dot
      local dot = server_name:find("%.")
      return server_name:sub(dot + 1)
    end
  end

  -- retrieves the certificate using the defined strategy
  function self.stragy_get_certificate(domain)
    local strategy = self.strategy()
    print("using strategy [" .. strategy.name() .. "] to fetch certificate data")
    return strategy.retrieve(domain)
  end

  -- retrieves the certificate to provide to clients
  function self.get_certificate()
    -- retrieves the domain
    local domain = self.get_ssl_domain()
    if domain == "" or domain == nil then
      ngx.log(ngx.ERR, "unable to parse domain out of SSL server name: " .. self.ssl.server_name())
      return
    end
    -- attempt reading data from cache first
    local from_cache = false
    local cert, key = self.cache.get_certificate(domain)
    if cert == nil or key == nil then
      -- certificate not in cache, retrieving from origin
      print("certificate not found in cache for domain: " .. domain)
      cert, key = self.stragy_get_certificate(domain)
      if cert == nil or key == nil then
        ngx.log(ngx.ERR, "cannot retrieve certificate data for domain: " .. domain)
        return
      end
      print("storing certificate for domain ".. domain .." in shared cache")
      self.cache.set_certificate(domain, cert, key)
    else
      -- certificate loaded from cache
      from_cache = true
      print("certificate retrieved from cache for domain: " .. domain)
    end
    return cert, key, domain, from_cache
  end

  -- function to be called within ssl_certificate_by_lua_block
  -- this is where all the magic happens
  function self.handle()
   print("handling SSL handshake for server name: " .. self.ssl.server_name())
   local cert, key, domain, from_cache = self.get_certificate()
    if cert == nil or key == nil then
      ngx.log(ngx.ERR, "something went wrong while attempting to fetch certificate data")
      return
    end
    -- clears the original SSL certificates
    local ok, err = self.ssl.clear_certs()
    if not ok then
      ngx.log(ngx.ERR, err)
      return
    end
    -- assign and return the retrieved certificate
    self.ssl.set_cert(self.ssl.parse_pem_cert(cert))
    self.ssl.set_priv_key(self.ssl.parse_pem_priv_key(key))
    print("returned SSL certificate for domain: " .. domain .. "; from_cache=" .. tostring(from_cache))
  end

  -- returns the object instance
  return self
end

return tls_manager
