# lua-resty-tls-manager

Library to automatically provide SSL certificate files

## Configuration

On `nginx.conf`:

```
http {
  ...

  -- this is mandatory
  lua_shared_dict tls 64m;

  -- optional, but speeds up modules loading
  init_by_lua_block {
    require("resty.tls_manager").preload_modules()
  }

  ...
}
```

On the relevant `conf.d/site.conf`:

```
server {
  listen [::]:80;
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name site.example.com;

  # nginx always expect certificate configuration to be
  # present. These will be used when tls manager fails
  # to provide a valid certificate.
  ssl_certificate /path/to/certs/invalid.crt;
  ssl_certificate_key /path/to/certs/invalid.key;

  ssl_certificate_by_lua_block {
    local tls_mgr = require("resty.tls_manager").new({
      strategy = "files",
      -- other options here --
    })
    tls_mgr:handle()
  }

}
```

## Strategies

Each strategy defines the way how certificates are retrieved from
the origin

### Files

```
local tls_mgr = require("resty.tls_manager").new({
  -- strategy to use
  strategy     = "files",         -- default: "files"
  -- certificate cache ttl,
  cache_ttl    = 300,             -- default: 3600
  -- path where to load certificates from
  certs_path   = "/path/to/certs" -- default: "/etc/pki/tls/certs"
  -- path where to load certificate keys from
  keys_path    = "/path/to/keys"  -- default: "/etc/pki/tls/private"
  -- certificates files prefix
  certs_prefix = "prefix."        -- default: "wildcard."
  -- certificates key files prefix
  keys_prefix  = "prefix."        -- default: "wildcard."
  -- certificate files extension
  certs_ext    = ".ext1"          -- default: ".crt"
  -- certificate key files extension
})
tls_mgr:handle()
```

### Consul

Requires: [lua-resty-consul](https://github.com/hamishforbes/lua-resty-consul)

```
local tls_mgr = require("resty.tls_manager").new({
  -- strategy to use
  strategy     = "consul",        -- default: "files"
  -- certificate cache ttl,
  cache_ttl    = 300,             -- default: 3600
  -- path where to load certificates from
  certs_path   = "path/to/certs"  -- default: "tls/production/certs"
  -- path where to load certificate keys from
  keys_path    = "path/to/keys"   -- default: "tls/production/keys"
  -- certificates files prefix
  certs_prefix = "prefix."        -- default: ""
  -- certificates key files prefix
  keys_prefix  = "prefix."        -- default: ""
  -- consul host
  consul_host  = "192.168.1.2"    -- default: "127.0.0.1"
  -- consul port
  consul_port  = 8500             -- default: 8500
  -- consul token
  consul_token = "xxxx-yyy-zzz"   -- default: ""
  -- consul connect timeout (ms)
  consul_connect_timeout = 5000   -- default: 3000
  -- consul read timeout (ms)
  consul_read_timeout = 5000      -- default: 3000
})
tls_mgr:handle()
```
