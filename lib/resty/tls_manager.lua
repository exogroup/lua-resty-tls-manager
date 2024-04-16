
local tlsmgr = {}

tlsmgr.settings = {}
tlsmgr.instance = nil
tlsmgr.ssl = require "ngx.ssl"

-- private function which returns an instance of
-- the actual tls manager object
local function new()
  local self = {}

  -- default values
  self.settings = tlsmgr.settings

  -- configure the shared cache
  self.cache = require("resty.tls_manager.cache").new(
    self.settings.cache_name,
    self.settings.cache_ttl
  )
  if self.cache == nil then
    ngx.log(ngx.ERR, "unable to initialize the shared cache")
    return
  end

  -- returns the ngx.ssl instance
  function self.ssl()
    return tlsmgr.ssl
  end

  -- returns the ssl server name
  function self.ssl_server_name()
    return self.ssl().server_name()
  end

  -- configured the connection ssl certificate
  function self.ssl_set_certificate(cert, key)
    local ssl = self.ssl()
    local cert_pem = ssl.parse_pem_cert(cert)
    local key_pem = ssl.parse_pem_priv_key(key)
    local ok, err = ssl.clear_certs()
    if not ok then
      ngx.log(ngx.ERR, err)
      return false
    end
    ssl.set_cert(cert_pem)
    ssl.set_priv_key(key_pem)
    return true
  end

  -- returns the strategy object
  function self.strategy()
    local name = self.settings.strategy
      or "files"
    local prefix = self.settings.strategy_prefix
      or "resty.tls_manager.strategy"

    local o = prefix .. "." .. name
    if not pcall(require, o) then
      ngx.log(ngx.ERR, "strategy not found or syntax error in: " .. name ..", prefix: ".. prefix)
    end
    -- instantiate and returns the strategy object
    -- passing the object constructor arguments
    return require(o).new(self.settings)
  end

  -- retrieves the domain name out of the
  -- SSL server name provided by nginx
  function self.get_ssl_domain()
    return self.get_domain(self.ssl_server_name())
  end

  function self.get_domain(server_name)
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
      ngx.log(ngx.ERR, "unable to parse domain out of SSL server name: " .. self.ssl_server_name())
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
      if not self.cache.set_certificate(domain, cert, key) then
        ngx.log(ngx.ERR, "failed to store the certificate into shared cache")
        return
      end
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
   print("handling SSL handshake for server name: " .. self.ssl_server_name())
   local cert, key, domain, from_cache = self.get_certificate()
    if cert == nil or key == nil then
      ngx.log(ngx.ERR, "something went wrong while attempting to fetch certificate data")
      return
    end
    -- assign and return the retrieved certificate
    if self.ssl_set_certificate(cert, key) then
      print("returned SSL certificate for domain: " .. domain .. "; from_cache=" .. tostring(from_cache))
    else
      print("error while returning the SSL certificate for domain: ".. domain)
    end
  end

  -- function to be called for clearing the cache for a domain
  function self.clear_cache(domain)
    if domain == "" or domain == nil then
      ngx.log(ngx.ERR, "refusing to handle a clear cache request for an empty domain")
      return false
    end
    print("handling purging SSL certificate cache request for domain: ", domain)
    if self.cache.delete_certificate(domain) then
      print("SSL certificate cache cleared successfully for domain: ", domain)
      return true
    else
      ngx.log(ngx.ERR, "failed to clear SSL certificate cache for domain: ", domain)
      return false
    end
  end

  return self
end

-- configure the tls manager instance
function tlsmgr.configure(settings)
  tlsmgr.settings = settings or {}
  return tlsmgr
end

-- returns the tls manager instance
function tlsmgr.get_instance()
  if tlsmgr.instance == nil then
    tlsmgr.instance = new()
  end
  return tlsmgr.instance
end

-- shortcut
function tlsmgr.handle()
  return tlsmgr.get_instance().handle()
end

-- shortcut
function tlsmgr.clear_cache(domain)
  return tlsmgr.get_instance().clear_cache(domain)
end

return tlsmgr