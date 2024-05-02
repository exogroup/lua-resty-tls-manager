-- strategy: files
-- read the certificate file and key for the given domain
-- from specific directories in the filesystem.

local _M = {}

function _M.new(args)
  local self = require "resty.tls_manager.strategy"

  -- path to certificate files
  self.crt_path = args.crt_path or "/etc/nginx/ssl/{{domain}}.crt"
  -- path to certificate keys
  self.key_path = args.key_path or "/etc/nginx/ssl/{{domain}}.key"
  -- replace wildcard '*.' from domain with string
  self.wildcard_replace = args.wildcard_replace or nil

  -- returns the contents of a file
  -- must be located on top as the order matters in Lua! 
  local function file_get_contents(file)
    local f = io.open(file, "r")
    if not f then
      return false, nil
    end
    local data = f:read("a*")
    f:close()

    return true, data
  end

  -- returns the strategy name for loggin purposes
  function self.name()
    return "files"
  end

  -- returns both the certificate file and key for the given domain
  function self.get_certificate(domain)
    -- lookup logic
    local crt_path = self.replace_vars(self.crt_path)
    local crt_found, crt = file_get_contents(crt_path)
    ngx.log(ngx.INFO, "crt=" .. crt_path .."; found=".. tostring(crt_found))

    local key_path = self.replace_vars(self.key_path)
    local key_found, key = file_get_contents(key_path)
    ngx.log(ngx.INFO, "key=" .. key_path .."; found=".. tostring(key_found))

    return crt, key
  end

  return self
end

return _M
