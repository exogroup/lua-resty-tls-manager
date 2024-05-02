# lua-resty-tls-manager

Automatically Provision SSL Certificate Files

> [!WARNING]
> This library is under active development and may undergo changes without prior notice.<br />
> Production use is NOT recommended.

## Requirements
* [lua-resty-http](https://github.com/ledgetech/lua-resty-http)

## Configuration

### Nginx Configuration (`nginx.conf`)

```nginx
http {
  # Define a shared dictionary named 'tls' with a size of 64 MB.
  # This dictionary is used for caching TLS-related data.
  lua_shared_dict tls 64m;

  # Optional: initialize TLS manager with configuration parameters.
  init_by_lua_block {
    local tlsmgr = require("resty.tls_manager")

    -- Configure optional parameters for TLS manager.
    -- These parameters will be applied across all server names in nginx.
    tlsmgr.configure({
      strategy = "consul",
      crt_path = "foo/crt/{{domain}}",
      key_path = "foo/key/{{domain}}",
    })
  }

}
```

### Server Configuration (`conf.d/<site>.conf`)

```nginx
server {
  # Listen on port 443 for SSL connections.
  listen 443 ssl;

  # Define the server name for this block.
  server_name site.example.com;

  # Nginx expects certificate configuration.
  # These will be fallbacks if TLS manager fails to provide
  # a valid certificate.
  ssl_certificate /path/to/certs/invalid.crt;
  ssl_certificate_key /path/to/certs/invalid.key;

  # Disable nginx OCSP stapling as it will be handled by TLS manager.
  ssl_stapling off;

  # Configure SSL certificate dynamically using Lua.
  ssl_certificate_by_lua_block {
    -- Initialize the TLS manager object.
    local tlsmgr = require("resty.tls_manager")

    -- Override parameters set from init_by_lua_block.
    tlsmgr.configure({
      -- Custom parameters can be set here.
    })

    -- Alternatively, use this syntax if you don't want to change
    -- all configuration parameters but just a few.
    tlsmgr.settings.crt_path = "/path/to/my/certs"
    tlsmgr.settings.key_path = "/path/to/my/keys"

    -- Finally, handle the SSL connection.
    tlsmgr.handle()
  }
}
```

## Configuration Options

* `cache_name`: Name of the `ngx.SHARED_DICT` cache (default: `tls`)
* `cache_ttl`: TTL of the TLS cache in seconds (default: `3600`)
* `strategy`: Name of the strategy to use (default: `files`)
* `strategy_prefix`: Lua path for the strategy files (default: `resty.tls_manager.strategy`). Change this for custom strategy implementations.
* `ocsp`: Enables OCSP stapling (default: `true`)
* `ocsp_cache`: Enables OCSP response caching (default: `true`)
* `ocsp_use_max_age`: Use the 'max-age' parameter from the 'Cache-Control header to determine for how much an OCSP response should be cached (default: `true`)
* `ocsp_default_cache_ttl`: Amount of time in seconds for the OCSP responses to be cached when `ocsp_use_max_age` is `false`, the header is not provided or the resulting TTL is less or equal to 0 (requires: `ocsp=true`, `ocsp_cache=true`)
* `ocsp_max_age_offset`: Number to subtract from `max-age` to calculate the actual TTL for the cache key (requires: `ocsp=true`, `ocsp_cache=true`, `ocsp_use_max_age=true`)
* `ocsp_connect_timeout`: HTTP connect timeout in milliseconds (ms) for the OCSP URL (default: `2000`, requires: `ocsp=true`, `ocsp_cache=true`)
* `ocsp_send_timeout`: HTTP send timeout in milliseconds (ms) for the OCSP URL (default: `2000`, requires: `ocsp=true`, `ocsp_cache=true`)
* `ocsp_read_timeout`: HTTP read timeout in milliseconds (ms) for the OCSP URL (default: `2000`, requires: `ocsp=true`, `ocsp_cache=true`)

## Strategies

Each strategy defines the way how certificates are retrieved from the origin.

### Files

```lua
local tlsmgr = require("resty.tls_manager")
tlsmgr.configure({
  -- Path where to load certificates from.
  crt_path = "/path/to/certs/{{domain}}.pem",  -- default: "/etc/nginx/ssl/{{domain}}.pem"
  -- Path where to load certificate keys from.
  key_path = "/path/to/keys/{{domain}}.key",   -- default: "/etc/nginx/ssl/{{domain}}.key"
  -- Replace *. in {{domain}} with custom string.
  wildcard_replace = "wildcard.",              -- default: nil
  -- Host, wildcard certificate lookup order.
  lookup_wildcard_first = false,               -- default: true
})
tlsmgr.handle()
```

### Consul

Requires: [lua-resty-consul](https://github.com/hamishforbes/lua-resty-consul)

```lua
local tlsmgr = require("resty.tls_manager").configure({
  -- Strategy to use.
  strategy = "consul",                   -- default: "files"
  -- Path where to load certificates from.
  crt_path = "path/to/certs/{{domain}}", -- default: "tls/production/certs"
  -- Path where to load certificate keys from.
  key_path = "path/to/keys/{{domain}}",  -- default: "tls/production/keys"
  -- Consul host.
  consul_host = "192.168.1.2",           -- default: "127.0.0.1"
  -- Consul port.
  consul_port = 8500,                    -- default: 8500
  -- Consul token.
  consul_token = "xxxx-yyy-zzz",         -- default: ""
  -- Consul SSL.
  consul_ssl = true,                     -- default: false
  -- Consul SSL peer verification.
  consul_ssl_verify = false,             -- default: true
  -- Consul SNI host.
  consul_sni_host = "foo.bar",           -- default: nil
  -- Consul connect timeout (ms).
  consul_connect_timeout = 5000,         -- default: 3000
  -- Consul read timeout (ms).
  consul_read_timeout = 5000,            -- default: 3000
})
tlsmgr.handle()
```

## On-demand SSL Cache Clearing

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

To clear a certificate from the shared cache, access `http://host/clear/example.com`.