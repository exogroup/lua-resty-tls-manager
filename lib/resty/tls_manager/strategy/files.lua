-- Strategy: files
-- Reads the certificate file and key for the given domain
-- from specific directories in the filesystem.

local tls_strategy_files = {}

function tls_strategy_files.new(args)
  local self = require "resty.tls_manager.strategy"

  -- path to certificate files
  self.crt_path = args.crt_path  or "/etc/nginx/ssl/{{domain}}.crt"
  -- path to certificate keys
  self.key_path = args.key_path  or "/etc/nginx/ssl/{{domain}}.key"

  -- returns the strategy name for loggin purposes
  function self.name()
    return "files"
  end

  -- returns the contents of a file
  local function file_get_contents(file)
    local f = io.open(file, "r")
    if not f then
      return
    end
    local data = f:read("a*")
    f:close()

    return data
  end

  -- returns both the certificate file and key for the given domain
  function self.get_certificate(domain, type)
    self.vars.domain = domain
    self.vars.type = type

    local crt_path = self.replace_vars(self.crt_path)
    local key_path = self.replace_vars(self.key_path)
    local crt = file_get_contents(crt_path)
    local key = file_get_contents(key_path)
    local found = (crt ~= nil and key ~= nil)

    print("crt=" .. crt_path ..", key=" .. key_path .. "; found=" .. tostring(found))

    return crt, key
  end

  return self
end

return tls_strategy_files
