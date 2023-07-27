local handler = require "kong.plugins.oidc.handler"

local function find_plugin()
    for plugin, err in kong.db.plugins:each(1000) do
      if err then
        return nil, err
      end
  
      if plugin.name == "oidc" then
        return plugin
      end
    end
  end

  return {
    ["/acme"] = {
      POST = function(self)
        local plugin, err = find_plugin()
        if err then
          return kong.response.exit(500, { message = err })
        elseif not plugin then
          return kong.response.exit(404)
        end
        local conf = plugin.config
  
        local host = self.params.host
        if not host or type(host) ~= "string" then
          return kong.response.exit(400, { message = "host must be provided and containing a single domain" })
        end
  
        -- we don't allow port for security reason in test_only mode
        if string_find(host, ":", 1, true) ~= nil then
          return kong.response.exit(400, { message = "port is not allowed in host" })
        end
  
        -- string "true" automatically becomes boolean true from lapis
        if self.params.test_http_challenge_flow == true then
          local domains_matcher = handler.build_domain_matcher(conf.domains)
          if not domains_matcher or not domains_matcher[host] then
            return kong.response.exit(400, { message = "problem found running sanity check for " .. host ..
                  ": host is not included in plugin config.domains"})
          end
  
          local check_path = string_format("http://%s/.well-known/acme-challenge/", host)
          local httpc = http.new()
          local res, err = httpc:request_uri(check_path .. "x")
          if not err then
            if ngx_re_match(res.body, "no Route matched with those values") then
              err = check_path .. "* doesn't map to a Route in Kong; " ..
                    "please refer to docs on how to create dummy Route and Service"
            elseif res.body ~= "Not found\n" then
              err = "unexpected response: \"" .. (res.body or "<nil>") .. "\""
              if res.status ~= 404 then
                err = err .. string_format(", unexpected status code: %d", res.status)
              end
            else
              return kong.response.exit(200, { message = "sanity test for host " .. host .. " passed"})
            end
          end
          return kong.response.exit(400, { message = "problem found running sanity check for " .. host .. ": " .. err})
        end
  
        local _, err = client.update_certificate(conf, host, nil)
        if err then
          return kong.response.exit(500, { message = "failed to update certificate: " .. err })
        end
        err = client.store_renew_config(conf, host)
        if err then
          return kong.response.exit(500, { message = "failed to store renew config: " .. err })
        end
        local msg = "certificate for host " .. host .. " is created"
        return kong.response.exit(201, { message = msg })
      end,
  
      PATCH = function()
        ngx_timer_at(0, client.renew_certificate)
        return kong.response.exit(202, { message = "Renewal process started successfully" })
      end,
    },
  
    ["/token"] = {
      GET = function(self)
        local plugin, err = find_plugin()
        if err then
          return kong.response.exit(500, { message = err })
        elseif not plugin then
          return kong.response.exit(404)
        end
  
        local conf = plugin.config
       
  
        local data = { client_id = conf.client_id,}
        
        return kong.response.exit(200, { data = data })
      end,
    },
  
    ["/acme/certificates/:certificates"] = {
      GET = function(self)
        local plugin, err = find_plugin()
        if err then
          return kong.response.exit(500, { message = err })
        elseif not plugin then
          return kong.response.exit(404)
        end
  
        local conf = plugin.config
        local host = self.params.certificates
        local certkey, err = client.load_certkey(conf, host)
        if err then
          return kong.response.exit(500, { message = err })
        end
        if not certkey then
          return kong.response.exit(404, { message = "Certificate for host " .. host .. "not found in storage" })
        end
        return kong.response.exit(200, { data = parse_certkey(certkey) })
      end,
    },
  }