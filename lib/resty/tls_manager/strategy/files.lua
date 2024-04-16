-- Strategy: files
-- Reads the certificate file and key for the given domain
-- from specific directories in the filesystem.

local tls_strategy_files = {}

function tls_strategy_files.new(args)
  local self = {}

  -- path to certificate files
  self.certs_path   = args.certs_path   or "/etc/nginx/ssl"
  -- path to certificate keys
  self.keys_path    = args.keys_path    or "/etc/nginx/ssl"
  -- certificate file prefix
  self.certs_prefix = args.certs_prefix or ""
  -- certificate key filename prefix
  self.keys_prefix  = args.keys_prefix  or ""
  -- certificate file extension
  self.certs_suffix = args.certs_suffix or ".crt"
  -- certificate key extension
  self.keys_suffix  = args.keys_suffix  or ".key"

  -- returns the strategy name for loggin purposes
  function self.name()
    return "files"
  end

  -- returns the certificate file path
  function self.get_cert_file_path(domain)
    return self.certs_path .. "/" .. self.certs_prefix .. domain .. self.certs_suffix
  end

  -- returns the certificate key path
  function self.get_cert_key_path(domain)
    return self.keys_path  .. "/" .. self.keys_prefix  .. domain .. self.keys_suffix
  end

  -- returns both the certificate file and certificate key file paths
  function self.get_certificate_files(domain)
    return self.get_cert_file_path(domain),
           self.get_cert_key_path(domain)
  end

  -- returns the contents of a file
  function self.file_get_contents(file)
    local f = io.open(file, "r")
    if not f then
      ngx.log(ngx.ERR, "file cannot be read: " .. file)
      return
    end
    local data = f:read("a*")
    f:close()
    return data
  end

  -- returns both the certificate file and key for the given domain
  function self.retrieve(domain)
    local cert_file, key_file = self.get_certificate_files(domain)

    -- print useful debug information
    print("reading certificate file from: " .. cert_file)
    print("reading certificate key from: " .. key_file)

    return self.file_get_contents(cert_file),
           self.file_get_contents(key_file)
  end

  return self
end

return tls_strategy_files
