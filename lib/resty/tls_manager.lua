
local _M = {}

-- tlsmgr singleton instance
_M.instance = nil

-- constants for certificate types
_M.CERT_TYPE_HOST = "host"
_M.CERT_TYPE_WILDCARD = "wildcard"

-- table containing instance settings
_M.settings = {}

-- ngx.ssl instance
_M.ssl = require "ngx.ssl"
-- ngx.ocsp instance
_M.ocsp = require "ngx.ocsp"
-- resty.http.simple instance
_M.http = require "resty.http"

-- private function which returns an instance of
-- the actual tls manager object
local function new()
  local self = {}

  -- default settings
  self.settings = _M.settings

  -- configure the shared cache
  self.cache = require("resty.tls_manager.cache").new(
    self.settings.cache_name,
    self.settings.cache_ttl
  )
  if self.cache == nil then
    ngx.log(ngx.ERR, "unable to initialize the shared cache")
    return
  end

  -- return the strategy object
  local function _strategy()
    local name = self.settings.strategy
    if name == nil then
      -- default strategy
      name = "files"
    end
    local prefix = self.settings.strategy_prefix
    if prefix == nil then
      -- default strategy prefix
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

  -- retrieve a boolean parameter from settings with optional default value.
  -- if the parameter is not found in settings, the default value is returned.
  local function bool_param(name, default)
    if default == nil then default = true end
    if self.settings[name] == nil then
      return default
    else
      return self.settings[name] == true
    end
  end

  -- retrieves the TTL for caching OCSP responses based on the Cache-Control header.
  -- if the header is not present or parsing is disabled, falls back to default TTL.
  local function ocsp_get_cache_ttl(res)
    local ttl = self.ocsp_default_cache_ttl
    -- check if parsing of Cache-Control header is disabled
    if not self.ocsp_use_max_age_header then
      ngx.log(ngx.NOTICE, "parsing of the Cache-Control header is disabled from config. Using default OCSP cache TTL: ".. ttl)
      return ttl
    end
    -- retrieve Cache-Control header
    local hdr = res.headers["Cache-Control"]
    -- if header is not present, log warning and return default TTL
    if not hdr then
      ngx.log(ngx.WARN, "unable to retrieve the Cache-Control header. Using default OCSP cache TTL: ".. ttl)
      return ttl
    end
    -- extract max-age from Cache-Control header
    local max_age = tonumber(hdr:match("max%-age=(%d+)"))
    ngx.log(ngx.INFO, "retrieved max-age=".. max_age .." from Cache-Control header")
    -- calculate TTL based on max-age and offset
    if (max_age - self.ocsp_max_age_offset) > 0 then
      ttl = max_age - self.ocsp_max_age_offset
    end

    return ttl
  end

  -- caches the OCSP response with specified TTL.
  -- if caching is disabled or cache control headers are not present, falls back to default TTL.
  local function ocsp_cache_response(cache_key, response)
    -- check if ocsp caching is enabled
    if not self.ocsp_cache then
      ngx.log(ngx.INFO, "OCSP caching is disabled from config. Not caching OCSP response.")
      return
    end
    -- calculate the cache TTL
    local cache_ttl = ocsp_get_cache_ttl(response)
    -- cache the OCSP response
    local ok, err = self.cache.ocsp_set(cache_key, response.body, cache_ttl)
    if ok then
      ngx.log(ngx.NOTICE, "OCSP response has been cached; key=".. cache_key .."; ttl=" .. cache_ttl)
    else
      ngx.log(ngx.ERR, "unable to cache OCSP response; key=" .. cache_key .. "; ERROR: " .. err)
    end
  end

  -- make a request to the OCSP responder to obtain the OCSP response.
  -- if caching is enabled, it checks the cache first before making a request.
  local function ocsp_make_request(req, url, der_cert_chain)
    if not self.ocsp then
      ngx.log(ngx.INFO, "OCSP responder disabled from config")
      return false
    end

    -- OCSP response
    local ocsp_response = nil
    -- OCSP cache key
    local ocsp_cache_key = nil
    -- Is OCSP response coming from cache?
    local from_cache = true
    -- Is OCSP response valid?
    local ocsp_valid_response = false

    if self.ocsp_cache then
      -- cache key for OCSP response
      ocsp_cache_key = ngx.md5(req .. string.char(0) .. url)
      -- cached OCSP response
      ocsp_response = self.cache.ocsp_get(ocsp_cache_key)
      -- debug
      ngx.log(ngx.NOTICE, "checking if a cached OCSP response exists; key=".. ocsp_cache_key)
    else
      ngx.log(ngx.NOTICE, "OCSP cache disabled from config")
    end

    if not ocsp_response then
      -- instantiate a new HTTP client object
      local httpc = _M.http.new()

      -- configure HTTP timeouts
      httpc:set_timeouts(
        self.ocsp_connect_timeout,
        self.ocsp_send_timeout,
        self.ocsp_read_timeout
      )
      ngx.log(ngx.NOTICE, "executing HTTP POST request to OCSP URL: ".. url)
      local res, err = httpc:request_uri(url, {
        method = "POST",
        body = req,
        headers = {
          Host = host,
          ["Content-Type"] = "application/ocsp-request",
        },
      })

      -- validate HTTP request
      if not res then
        ngx.log(ngx.ERR, "OCSP responder query failed: ", err)
        return false
      end
      local http_status = res.status
      if http_status ~= 200 then
        ngx.log(ngx.ERR, "OCSP responder returns bad HTTP status code ", http_status)
        return false
      end

      -- OCSP response got from the responder
      ocsp_response = res.body

      -- validate OCSP response and cache when valid
      if ocsp_response and #ocsp_response > 0 then
        local ok, err = _M.ocsp.validate_ocsp_response(ocsp_response, der_cert_chain)
        if not ok then
          ngx.log(ngx.ERR, "failed to validate OCSP response: ", err)
          return false
        end
        ocsp_valid_response = true
        -- cache the OCSP response
        ocsp_cache_response(ocsp_cache_key, res)
        -- response not coming from cache
        from_cache = false
      end
    else
      -- response is cached, so implicitly valid
      ocsp_valid_response = true
    end
    
    return ocsp_valid_response, ocsp_response, from_cache
    
  end

  -- OCSP responder method
  -- adapted from https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ocsp.md
  local function ocsp_responder(crt)
    local der_cert_chain, err = _M.ssl.cert_pem_to_der(crt)
    local ocsp_url, err = _M.ocsp.get_ocsp_responder_from_der_chain(der_cert_chain)
    if not ocsp_url then
      ngx.log(ngx.ERR, "failed to get OCSP responder: ", err)
      return
    end
    -- create OCSP request
    local ocsp_req, err = _M.ocsp.create_ocsp_request(der_cert_chain)
    if not ocsp_req then
      ngx.log(ngx.ERR, "failed to create OCSP request: ", err)
      return
    end
    -- make and cache OCSP request
    local ocsp_valid_res, ocsp_response, from_cache = ocsp_make_request(ocsp_req, ocsp_url, der_cert_chain)
    if ocsp_valid_res then
      -- set the OCSP stapling
      local ok, err = _M.ocsp.set_ocsp_status_resp(ocsp_response)
      if not ok then
        ngx.log(ngx.ERR, "failed to set OCSP status response: ", err)
        return
      end
      ngx.log(ngx.INFO, "OCSP status set successfully; from_cache=".. tostring(from_cache))
    else
      ngx.log(ngx.ERR, "something went wrong")
    end
  end

  -- configure strategy
  self.strategy = _strategy()

  -- OCSP settings
  self.ocsp = bool_param("ocsp", true)
  self.ocsp_cache = bool_param("ocsp_cache", true)
  self.ocsp_use_max_age_header = bool_param("ocsp_use_max_age_header", true)
  self.ocsp_default_cache_ttl = self.settings.ocsp_default_cache_ttl or 300
  self.ocsp_max_age_offset = self.settings.ocsp_max_age_offset or 300
  self.ocsp_connect_timeout = self.settings.ocsp_connect_timeout or 2000
  self.ocsp_read_timeout = self.settings.ocsp_read_timeout or 2000
  self.ocsp_send_timeout = self.settings.ocsp_send_timeout or 2000
  
  -- return the ssl server name
  function self.ssl_server_name()
    return _M.ssl.server_name()
  end

  -- return the ssl server domain
  function self.ssl_server_domain()
    return self.parse_domain(self.ssl_server_name())
  end

  -- return *. with the ssl server domain
  function self.ssl_wildcard_domain()
    return "*." .. self.ssl_server_domain()
  end

  -- return true if the domain begins with *.
  function self.is_wildcard(domain)
    return string.sub(domain, 1, 2) == "*."
  end

  -- parses the domain out of the server name
  -- example.com         -> example.com
  -- bar.example.com     -> example.com
  -- foo.bar.example.com -> bar.example.com
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

  -- configure the connection ssl certificate
  function self.ssl_set_certificate(cert, key)
    local cert_pem = _M.ssl.parse_pem_cert(cert)
    local key_pem = _M.ssl.parse_pem_priv_key(key)
    local ok, err = _M.ssl.clear_certs()
    if not ok then
      ngx.log(ngx.ERR, err)
      return false
    end
    _M.ssl.set_cert(cert_pem)
    _M.ssl.set_priv_key(key_pem)
    return true
  end

  -- return the domains to be looked up in cache/strategy
  function self.get_lookup_domains()
    local wildcard_first = self.settings.lookup_wildcard_first
    if wildcard_first == nil then  wildcard_first = true end

    -- change the order of the array depending on the parameter
    local idx_w = (wildcard_first and 1 or 2)
    local idx_h = (wildcard_first and 2 or 1)

    -- debug information
    ngx.log(ngx.INFO, "lookup order: [".. idx_w .."]wildcard, [".. idx_h .."]host")

    return ipairs({
      [idx_w] = {
        type = _M.CERT_TYPE_WILDCARD,
        name = self.ssl_wildcard_domain(),
      },
      [idx_h] = {
        type = _M.CERT_TYPE_HOST,
        name = self.ssl_server_name()
      },
    })
  end

  -- perform a strategy lookup for wildcard and host certificate
  function self.lookup_strategy(obj)
    local s_name = "[STRATEGY:".. obj.name() .."]" 
    for _, domain in self.get_lookup_domains() do
      print(s_name .." looking up ".. domain.type .." certificate for domain: " .. domain.name)
      local crt, key = obj.lookup(domain.name)
      if crt ~= nil and key ~= nil then
        return true, crt, key, domain.name, domain.type
      end
    end
    return false
  end

  -- perform a cache lookup for wildcard and host certificate
  function self.lookup_cache()
    local c_name = "[CACHE:".. self.cache.name .."]"
    for _, domain in self.get_lookup_domains() do
      print(c_name .. " looking up ".. domain.type .." certificate for domain: " .. domain.name)
      local crt, key = self.cache.get(domain.name)
      if crt ~= nil and key ~= nil then
        return true, crt, key, domain.name, domain.type
      end
    end
    return false
  end

  -- retrieves the certificate to provide to clients
  function self.get_certificate()
    local from_cache
    local found, crt, key, domain, type = self.lookup_cache()
    if found then
      from_cache = true
      print(type .. " certificate for domain ".. domain .." was found in cache")
    else
      from_cache = false
      print("certificate not found in cache, reverting to strategy lookup")
      found, crt, key, domain, type = self.lookup_strategy(self.strategy)
      -- FATAL: No certificate has been found
      if not found then
        ngx.log(ngx.ERR, "no certificate found for: ".. self.ssl_server_name())
        return false
      end
      -- Store the certificate in the shared cache
      if self.cache.set(domain, crt, key) then
        print(type .. " certificate for domain ".. domain .." stored in shared cache; ttl=".. self.cache.ttl)
      else
        ngx.log(ngx.WARN, "failed to store the certificate into shared cache")
      end
    end
    return found, crt, key, domain, type, from_cache
  end

  -- function to be called within ssl_certificate_by_lua_block
  -- this is where all the magic happens
  function self.handle()
    print("handling SSL handshake for server name: " .. self.ssl_server_name())
    local found, crt, key, domain, type, from_cache = self.get_certificate()
    -- Return the fallback certificate
    if not found then
      ngx.log(ngx.ERR, "returning the default fallback certificate")
      return
    end
    -- run oscp responder
    ocsp_responder(crt)
    -- assign and return the retrieved certificate
    if self.ssl_set_certificate(crt, key) then
      local from_cache_s = tostring(from_cache)
      print("returning ".. type .. " SSL certificate for domain: " .. domain .. "; from_cache=" .. from_cache_s)
    else
      print("error while returning the SSL certificate for domain: ".. domain)
    end
  end

  -- function to be called for clearing the cache for a domain
  function self.clear_cache(server_name)
    local res, type

    if server_name == "" or server_name == nil then
      ngx.log(ngx.ERR, "refusing to handle a clear cache request for an empty domain")
      return false
    end

    if self.is_wildcard(server_name) then
      type = _M.CERT_TYPE_WILDCARD
    else
      type = _M.CERT_TYPE_HOST
    end

    print("handling purging ".. type .." SSL certificate cache request for: ", server_name)
    if self.cache.delete_certificate(server_name, type) then
      print(type .. " SSL certificate cache cleared successfully for: ", server_name)
      res = true
    else
      ngx.log(ngx.ERR, "failed to clear ".. type .." SSL certificate cache for: ", server_name)
      res = false
    end

    return res
  end

  return self
end

-- configure the tls manager instance
function _M.configure(settings)
  _M.settings = settings or {}
  return _M
end

-- returns the tls manager instance
function _M.get_instance()
  if _M.instance == nil then
    _M.instance = new()
  end
  return _M.instance
end

-- shortcut
function _M.handle()
  return _M.get_instance().handle()
end

-- shortcut
function _M.clear_cache(domain)
  return _M.get_instance().clear_cache(domain)
end

return _M