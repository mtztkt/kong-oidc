local M = {}

local function shouldIgnoreRequest(patterns)
  if (patterns) then
    for _, pattern in ipairs(patterns) do
      local isMatching = not (string.find(ngx.var.uri, pattern) == nil)
      if (isMatching) then return true end
    end
  end
  return false
end

function M.shouldProcessRequest(config)
  return not shouldIgnoreRequest(config.filters)
end

local function shouldIgnoreRequestMethod(patterns)
  if (patterns) then
    ngx.log(ngx.DEBUG, "3121212OidcHandler ignoring request method: ".. ngx.var.request_method)
    for _, pattern in ipairs(patterns) do
      ngx.log(ngx.DEBUG, "421212OidcHandler ignoring request method: ".. ngx.var.request_method)
      local isMatching = not (string.find(ngx.var.request_method, pattern) == nil)
      if (isMatching) then 
        ngx.log(ngx.DEBUG, "121212OidcHandler ignoring request method: ".. ngx.var.request_method)
        return true 
      end
    end
  end
  return false
end

function M.shouldProcessRequestMethod(config)
  return  shouldIgnoreRequestMethod(config.ignore_request_methods)
end

return M
