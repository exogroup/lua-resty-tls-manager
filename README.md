# lua-resty-tls-manager

Library to automatically provide SSL certificate files

## Configuration

On `nginx.conf`:

```nginx
http {
  # ... #

  # this must match the 'cache_name' parameter
  lua_shared_dict tls 64m;

  # optional
  init_by_lua_block {
    local tlsmgr = require("resty.tls_manager")
    tlsmgr.configure({
      -- common parameters go here
    })
  }

  # ... #
}
```

On the relevant `conf.d/<site>.conf`:

```nginx
server {
  listen 443 ssl;

  server_name site.example.com;

  # nginx always expect certificate configuration to be
  # present. These will be used when tls manager fails
  # to provide a valid certificate.
  ssl_certificate /path/to/certs/invalid.crt;
  ssl_certificate_key /path/to/certs/invalid.key;

  ssl_certificate_by_lua_block {
    local tlsmgr = require("resty.tls_manager")
    -- override parameters set from init_by_lua_block
    tlsmgr.configure({
      -- custom parameters go here
    })
    -- or if you want to change only a few params
    tlsmgr.settings.certs_path = "/path/to/my/certs"
    tlsmgr.settings.keys_path = "/path/to/my/keys"
    -- finally handle the SSL connection
    tls_mgr.handle()
  }

}
```

## Strategies

Each strategy defines the way how certificates are retrieved from
the origin

### Files

```lua
local tlsmgr = require("resty.tls_manager")
tlsmgr.configure({
  -- strategy to use
  strategy = "files",                          -- default: "files"
  -- strategy prefix (for custom implementations)
  strategy_prefix = "my.strategy",             -- default: "resty.tls_manager.strategy"
  -- ngx.shared[] dictionary name
  cache_name = "foo",                          -- default: "tls"
  -- certificate cache ttl,
  cache_ttl = 300,                             -- default: 3600
  -- path where to load certificates from
  crt_path = "/path/to/certs/{{domain}}.pem",  -- default: "/etc/nginx/ssl/{{domain}}.pem"
  -- path where to load certificate keys from
  key_path = "/path/to/keys/{{domain}}.key",   -- default: "/etc/nginx/ssl"
})
tlsmgr.handle()
```

### Consul

Requires: [lua-resty-consul](https://github.com/hamishforbes/lua-resty-consul)

```lua
local tlsmgr = require("resty.tls_manager").configure({
  -- strategy to use
  strategy = "consul",                   -- default: "files"
  -- strategy prefix (for custom implementations)
  strategy_prefix = "my.strategy",       -- default: "resty.tls_manager.strategy"
  -- certificate cache ttl,
  cache_ttl = 300,                       -- default: 3600
  -- path where to load certificates from
  crt_path = "path/to/certs/{{domain}}", -- default: "tls/production/certs"
  -- path where to load certificate keys from
  key_path = "path/to/keys/{{domain}}",  -- default: "tls/production/keys"
  -- consul host
  consul_host = "192.168.1.2",           -- default: "127.0.0.1"
  -- consul port
  consul_port = 8500,                    -- default: 8500
  -- consul token
  consul_token = "xxxx-yyy-zzz",         -- default: ""
  -- consul ssl
  consul_ssl = true,                     -- default: false
  -- consul ssl peer verification
  consul_ssl_verify = false,             -- default: true
  -- consul sni host
  consul_sni_host = "foo.bar",           -- default: nil
  -- consul connect timeout (ms)
  consul_connect_timeout = 5000,         -- default: 3000
  -- consul read timeout (ms)
  consul_read_timeout = 5000,            -- default: 3000
})
tlsmgr.handle()
```

## On-demand SSL cache clearing
```nginx
server {
  listen 80 default;
  server_name localhost;

  location ~ ^/clear/(?<domain>[^/]+)$ {
    content_by_lua_block {
      local tlsmgr = require("resty.tls_manager")
      if not tlsmgr.clear_cache(ngx.var.domain) then
        ngx.exit(500)
      end
    }
  }
}
```
Then access `http://host/clear/example.com` to have the certificate
removed from the shared cache.
