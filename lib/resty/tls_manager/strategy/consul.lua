-- Strategy: consul
-- Reads the certificate file and key for the given domain
-- from specific paths in Consul KV store

local tls_strategy_consul = {}

function tls_strategy_consul.new(args)
  local self = {}

  -- loads consul object
  self.consul = require("resty.consul")

  -- certificate files path in Consul KV
  self.crt_path        = args.crt_path               or "tls/{{domain}}/crt"
  -- certificate keys path in Consul KV
  self.key_path        = args.key_path               or "tls/{{domain}}/key"
  -- consul host
  self.host            = args.consul_host            or "127.0.0.1"
  -- consul port
  self.port            = args.consul_port            or 8500
  -- consul token
  self.token           = args.consul_token           or ""
  -- consul ssl
  self.ssl             = args.consul_ssl             or false
  -- consul ssl verify
  self.ssl_verify      = args.consul_ssl_verify      or true
  -- consul sni host
  self.sni_host        = args_consul_sni_host        or nil
  -- consul connect timeout
  self.connect_timeout = args.consul_connect_timeout or (3 * 1000)
  -- consul read timeout
  self.read_timeout    = args.consul_read_timeout    or (3 * 1000)

  function self.name()
    return "consul"
  end

  -- returns both the certificate file and key for the given domain
  function self.get_certificate(domain, type)
    self.vars.domain = domain
    self.vars.type = type

    -- instantiates the consul object
    local consul = self.consul:new({
      host            = self.host,
      port            = self.port,
      connect_timeout = self.connect_timeout,
      read_timeout    = self.read_timeout,
      ssl             = self.ssl,
      ssl_verify      = self.ssl_verify,
      sni_host        = self.sni_host,
      default_args    = {
        token = self.token,
      }
    })
    -- print some useful debugging info
    local crt_kv_path = self.replace_vars(self.crt_path)
    local key_kv_path = self.replace_vars(self.key_path)

    -- execute the transaction and evaluate results
    local res, err = consul:txn({
      { KV = { Verb = "get", Key = crt_kv_path } },
      { KV = { Verb = "get", Key = key_kv_path } },
    })

    local found = tostring(res ~= nil or res ~= {})

    -- returns the error, if present
    if not res then
      ngx.log(ngx.ERR, err)
      return
    end

    print("crt=" .. crt_kv_path, ", key=" .. key_kv_path .. "; found=" .. found)

    -- returns the certificate and keys just read
    return res.body.Results[1].KV.Value or nil,
           res.body.Results[2].KV.Value or nil
  end

  -- returns the actual object
  return self
end

return tls_strategy_consul
