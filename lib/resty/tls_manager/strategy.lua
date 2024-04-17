local strategy = {}

strategy.vars = {}

function strategy.replace_vars(str, domain)
  local res = str:gsub("{{(%w+)}}", function(p)
    if strategy.vars[p] then
      return strategy.vars[p]
    end
    return p
  end)
  return res
end

function strategy.set_var(name, value)
  strategy.vars[name] = value
end

function strategy.get_var(name)
  return strategy.vars[name]
end

function strategy.name()
  error("missing name() implementation for this strategy")
end

function strategy.get_certificate(domain)
  error("missing get_certificate() implementation for this strategy")
end

return strategy