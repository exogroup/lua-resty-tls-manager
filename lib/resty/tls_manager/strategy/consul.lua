-- Strategy: consul
-- Reads the certificate file and key for the given domain
-- from specific paths in Consul KV store

local tls_strategy_consul = {}

function tls_strategy_consul.new(args)
  local self = {}

  -- loads consul object
  self.consul = require("resty.consul")

  -- certificate files path in Consul KV
  self.certs_path      = args.certs_path             or "tls/production/certs"
  -- certificate keys path in Consul KV
  self.keys_path       = args.keys_path              or "tls/production/keys"
  -- certificate files Consul key prefix
  self.certs_prefix    = args.certs_prefix           or ""
  -- certificate keys Consul key prefix
  self.keys_prefix     = args.keys_prefix            or ""
  -- certificate files Consul key suffix
  self.certs_suffix    = args.certs_suffix           or ""
  -- certificate keys Consul key suffix
  self.keys_suffix     = args.keys_suffix            or ""
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
  function self.retrieve(domain)
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
    local consul_key_cert_file = self.certs_path .. "/" .. self.certs_prefix .. domain .. self.certs_suffix
    local consul_key_cert_key  = self.keys_path .. "/" .. self.keys_prefix .. domain .. self.keys_suffix

    print("retrieving certificate file from KV path " .. consul_key_cert_file)
    print("retrieving certificate key from KV path " .. consul_key_cert_key)

    -- execute the transaction and evaluate results
    local res, err = consul:txn({
      { KV = { Verb = "get", Key = consul_key_cert_file } },
      { KV = { Verb = "get", Key = consul_key_cert_key  } },
    })

    -- returns the error, if present
    if not res then
      ngx.log(ngx.ERR, err)
      return
    end

    -- returns the certificate and keys just read
    return res.body.Results[1].KV.Value or nil,
           res.body.Results[2].KV.Value or nil
  end

  -- returns the actual object
  return self
end

return tls_strategy_consul