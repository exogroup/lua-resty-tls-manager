local _M = {}

-- hold all the vars which can be replaced in crt_path and key_path
_M.vars = {}

-- return the name of the strategy
function _M.name()
  error("missing name() implementation in strategy object")
end

-- must return certificate and key
-- eg crt, key = stragegy.get_certificate(domain)
function _M.get_certificate(domain)
  error("missing get_certificate() implementation in strategy object")
end

-- replace the placeholders with vars values
function _M.replace_vars(str, domain)
  local res = str:gsub("{{(%w+)}}", function(p)
    if _M.vars[p] then
      return _M.vars[p]
    end
    return p
  end)
  return res
end

-- replace the wildcard symbol (*.) in the domain with a custom string
function _M.replace_wildcard(domain)
  if _M.wildcard_replace ~= nil then
    local replacement = _M.wildcard_replace
    return string.gsub(domain, "^*.", replacement)
  end
  return domain
end

-- wrapper function called by tls manager
-- put here all the common strategy stuff
function _M.lookup(domain)
  -- set variables for replacement
  _M.vars.strategy = _M.name()
  _M.vars.domain = _M.replace_wildcard(domain)
  -- call the strategy defined function
  local crt, key = _M.get_certificate(domain)
  -- return the result
  return crt, key
end

return _M