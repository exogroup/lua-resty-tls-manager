local _M = {}

function _M.new(name, ttl)
  local self = {}

  -- shared dict key to use
  self.name = name or "tls"
  -- default cache keys ttl
  self.ttl  = ttl or 3600
  -- validate shared cache dictionary
  self.cache = ngx.shared[self.name]
  if type(self.cache) ~= "table" then
    ngx.log(ngx.ERR, "shared dictionary [".. self.name .."] was not found")
    return
  end

  -- split cert+key by a NULL char
  local function split(data)
    if data then
      -- %z is NULL char
      -- https://www.lua.org/pil/20.2.html
      return string.match(data,"^([^%z]+)%z([^%z]+)$")
    end
  end

  -- join cert+key with a NULL char
  local function join(crt, key)
    return crt .. string.char(0) .. key
  end

  -- store cert+key in the shared cache
  function self.set(domain, crt, key)
    return self.cache:set(domain, join(crt,key), self.ttl)
  end

  -- retrieve cert+key from the shared cache
  function self.get(domain)
    return split(self.cache:get(domain))
  end

  -- delete cert+key stored in shared cache
  function self.delete_certificate(domain, type)
    return self.cache:delete(domain)
  end

  -- store an ocsp response for a certificate in cache
  function self.ocsp_set(key, response, ttl)
    local ocsp_key = "ocsp:" .. key
    return self.cache:set(ocsp_key, response, ttl)
  end

  -- retrieve an ocsp response for a certificate from cache
  function self.ocsp_get(key)
    local ocsp_key = "ocsp:" .. key
    return self.cache:get(ocsp_key)
  end

  -- calls flush_expired()
  function self.flush_expired()
    return self.cache:flush_expired()
  end

  return self
end

return _M