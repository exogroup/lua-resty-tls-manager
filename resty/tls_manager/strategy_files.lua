-- Strategy: files
-- Reads the certificate file and key for the given domain
-- from specific directories in the filesystem.

local tls_strategy_files = {}

function tls_strategy_files.new(args)
  local self = {}

  -- path to certificate files
  self.certs_path   = args.certs_path   or "/etc/pki/tls/certs"
  -- path to certificate keys
  self.keys_path    = args.keys_path    or "/etc/pki/tls/private"
  -- certificate file prefix
  self.certs_prefix = args.certs_prefix or "wildcard."
  -- certificate key filename prefix
  self.keys_prefix  = args.keys_prefix  or "wildcard."
  -- certificate file extension
  self.certs_ext    = args.certs_ext    or ".crt"
  -- certificate key extension
  self.keys_ext     = args.keys_ext     or ".key"

  -- returns the strategy name for loggin purposes
  function self.name()
    return "files"
  end

  -- returns the certificate file path
  function self.get_cert_file_path(domain)
    return self.certs_path .. "/" .. self.certs_prefix .. domain .. self.certs_ext
  end

  -- returns the certificate key path
  function self.get_cert_key_path(domain)
    return self.keys_path  .. "/" .. self.keys_prefix  .. domain .. self.keys_ext
  end

  -- returns both the certificate file and certificate key file paths
  function self.get_certificate_files(domain)
    return self.get_cert_file_path(domain),
           self.get_cert_key_path(domain)
  end

  -- checks if a file exists
  function self.file_exists(file)
    local f = io.open(file, "r")
    if f then
      f:close()
      return true
    else
      return false
    end
  end

  -- returns the contents of a file
  function self.file_get_contents(file)
    if not self.file_exists(file) then
      error("file cannot be read: " .. file)
      return
    end
    local f = io.open(file, "r")
    local data = ""
    if f then
      data = f:read("*a")
      f:close()
    end
    return data
  end

  -- returns both the certificate file and key for the given domain
  function self.retrieve(domain)
    local cert_file, key_file = self.get_certificate_files(domain)
    return self.file_get_contents(cert_file),
           self.file_get_contents(key_file)
  end

  return self
end

return tls_strategy_files
