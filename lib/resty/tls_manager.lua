
local tlsmgr = {}

tlsmgr.settings = {}
tlsmgr.instance = nil

tlsmgr.ssl = require "ngx.ssl"

tlsmgr.CERT_TYPE_HOSTNAME = "hostname"
tlsmgr.CERT_TYPE_WILDCARD = "wildcard"

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

  -- returns the strategy object
  local function init_strategy()
    local name = self.settings.strategy
    if name == nil then
      name = "files"
    end
    local prefix = self.settings.strategy_prefix
    if prefix == nil then
      prefix = "resty.tls_manager.strategy"
    end
    local strategy = prefix .. "." .. name
    if not pcall(require, strategy) then
      ngx.log(ngx.ERR, "strategy not found or syntax error in: " .. name ..", prefix: ".. prefix)
    end
    -- instantiate and returns the strategy object
    -- passing the object constructor arguments
    return require(strategy).new(self.settings)
  end

  -- configure strategy
  self.strategy = init_strategy()

  -- returns the ngx.ssl instance
  function self.ssl()
    return tlsmgr.ssl
  end

  -- returns the ssl server name
  function self.ssl_server_name()
    return self.ssl().server_name()
  end

  function self.ssl_server_domain()
    return self.parse_domain(self.ssl_server_name())
  end

  function self.parse_domain(server_name)
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

  function self.lookup_certificate(obj, mode)
    local hostname = self.ssl_server_name()
    local wildcard = self.ssl_server_domain()
    local certs = {}
    -- add standalone certificate only when it's different from wildcard
    if hostname ~= wildcard then
      certs[tlsmgr.CERT_TYPE_HOSTNAME] = hostname
    else
      print(mode .. " skip hostname certificate lookup since it matches wildcard: " .. wildcard)
    end
    certs[tlsmgr.CERT_TYPE_WILDCARD] = wildcard
    for type, domain in pairs(certs) do
      print(mode .. " lookup ".. type .." certificate for domain: " .. domain)
      local crt, key = obj.get_certificate(domain, type)
      if crt ~= nil and key ~= nil then
        return crt, key, type, domain
      end
    end
  end

  -- retrieves the certificate to provide to clients
  function self.get_certificate()
    -- attempt reading data from cache first
    local crt, key, type, domain = self.lookup_certificate(self.cache, "cache["..self.cache.name.."]")
    local from_cache = false
    if crt ~= nil and key ~= nil then
      from_cache = true
      print(type .. " certificate for domain [".. domain .."] was found in cache")
    else
      print("certificate not found in cache, reverting to strategy lookup")
      local strategy_s = "strategy[".. self.strategy.name() .."]"
      crt, key, type, domain = self.lookup_certificate(self.strategy, strategy_s)
      if crt == nil and key == nil then
        ngx.log(ngx.ERR, "no certificate found for: " .. self.ssl_server_name())
        return
      end
      print(type .. " certificate for domain ".. domain .." was found using ".. strategy_s)
      if self.cache.set_certificate(domain, type, crt, key) then
        print(type .. " certificate for domain ".. domain .." stored in shared cache; ttl=".. self.cache.ttl)
      else
        ngx.log(ngx.WARN, "failed to store the certificate into shared cache")
      end
    end
    return crt, key, domain, from_cache
  end

  -- function to be called within ssl_certificate_by_lua_block
  -- this is where all the magic happens
  function self.handle()
    print("handling SSL handshake for server name: " .. self.ssl_server_name())
    local crt, key, domain, from_cache = self.get_certificate()
    if crt == nil or key == nil then
      ngx.log(ngx.ERR, "something went wrong, empty certificate data")
      return
    end
    -- assign and return the retrieved certificate
    if self.ssl_set_certificate(crt, key) then
      local from_cache_s = tostring(from_cache)
      print("returned SSL certificate for domain: " .. domain .. "; from_cache=" .. from_cache_s)
    else
      print("error while returning the SSL certificate for domain: ".. domain)
    end
  end

  -- function to be called for clearing the cache for a domain
  function self.clear_cache(server_name)
    if server_name == "" or server_name == nil then
      ngx.log(ngx.ERR, "refusing to handle a clear cache request for an empty domain")
      return false
    end

    local types = {}
    if server_name ~= self.parse_domain(server_name) then
      table.insert(types, tlsmgr.CERT_TYPE_HOSTNAME)
    end
    table.insert(types, tlsmgr.CERT_TYPE_WILDCARD)

    local res = true

    print("handling purging SSL certificate cache request for: ", server_name)
    for _, type in ipairs(types) do
      if self.cache.delete_certificate(server_name, type) then
        print(type .. " SSL certificate cache cleared successfully for: ", server_name)
      else
        ngx.log(ngx.ERR, "failed to clear SSL certificate cache for: ", server_name)
        res = false
      end
    end

    return res
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