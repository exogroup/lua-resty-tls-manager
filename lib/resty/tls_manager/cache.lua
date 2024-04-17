local cache = {}

function cache.new(name, ttl)
  local self = {}

  -- shared dict key to use
  self.name = name or "tls"
  -- default cache keys ttl
  self.ttl  = ttl or 3600

  self.cache = ngx.shared[self.name]
  if type(self.cache) ~= "table" then
    ngx.log(ngx.ERR, "shared dictionary [".. self.name .."] was not found")
    return
  end

  -- returns the certificate file cache key name
  function self.crt(domain, type)
    return "crt--" .. type .. "--" .. domain
  end

  -- returns the certificate key cache key name
  function self.key(domain, type)
    return "key--" .. type .. "--" .. domain
  end

  -- retrieves the certificate for a domain
  -- stored in shared cache. Returns nil when
  -- the certificate is not found
  function self.get_certificate_file(domain, type)
    local key = self.crt(domain, type)
    return self.cache:get(key)
  end

  -- retrieves the certificate key for a domain
  -- stored in shared cache. Returns nil when
  -- the keys is not found
  function self.get_certificate_key(domain, type)
    local key = self.key(domain, type)
    return self.cache:get(key)
  end

  -- stores the certificate for a domain in the
  -- shared cache for later retrieval
  function self.set_certificate_file(domain, type, data)
    local key = self.crt(domain, type)
    return self.cache:set(key, data, self.ttl)
  end

  -- stores the certificate key for a domain in the
  -- shared cache for later retrieval
  function self.set_certificate_key(domain, type, data)
    local key = self.key(domain, type)
    return self.cache:set(key, data, self.ttl)
  end

  -- stores both certificate file and key in the
  -- shared cache for later retrieval
  function self.set_certificate(domain, type, crt, key)
    return self.set_certificate_file(domain, type, crt) and
           self.set_certificate_key(domain, type, key)
  end

  -- retrieve both certificate file and key from
  -- the shared cache
  function self.get_certificate(domain, type)
    return self.get_certificate_file(domain, type),
           self.get_certificate_key(domain, type)
  end

  -- deletes the certificate file from the
  -- shared cache
  function self.delete_certificate_file(domain, type)
    local key = self.crt(domain, type)
    return self.cache:delete(key)
  end

  -- deletes the certificate key from the
  -- shared cache
  function self.delete_certificate_key(domain, type)
    local key = self.key(domain, type)
    return self.cache:delete(key)
  end

  -- deletes both certificate file and key from
  -- the shared cache
  function self.delete_certificate(domain, type)
    return self.delete_certificate_file(domain, type) and
           self.delete_certificate_key(domain, type)
  end

  -- calls flush_expired()
  function self.flush_expired()
    return self.cache:flush_expired()
  end

  return self
end

return cache