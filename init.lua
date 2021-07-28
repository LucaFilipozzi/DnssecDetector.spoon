---- === DnssecDetector === ----
---
--- Receive notifications every time internet becomes (un)reachable,
--- updating configured domain name servers based on whether DoT
--- (DNS-over-TLS) is available or not.
---
--- Download: https://github.com/LucaFilipozzi/DnssecDetector.spoon

-- Copyright (C) 2021 Luca Filipozzi

local obj = {}
obj.__index = obj
obj.name = "DnssecDetector"
obj.version = "1.0"
obj.author = "Luca Filipozzi"
obj.license = "BSD-3-Clause - https://opensource.org/licenses/BSD-3-Clause"
obj.homepage = "https://github.com/LucaFilipozzi/DnssecDetector.spoon"

--- DnssecDetector:init()
--- Method
--- Initialize the DnssecDetector spoon
function obj:init()
  self.networkConfiguration = hs.network.configuration.open()
  self.networkReachability = hs.network.reachability.internet()
  self.logger = hs.logger.new(obj.name)
end

--- DnssecDetector:start()
--- Method
--- Starts the DnssecDetector spoon
---
--- Returns:
--- * The DnssecDetector object
function obj:start()
  self.menubarItem = hs.menubar.new()

  self.networkConfiguration
    :monitorKeys("State:/Network/Global/DNS")
    :setCallback(hs.fnutils.partial(self.networkConfigurationCallback, self))
    :start()
  self:networkConfigurationCallback(nil)

  self.networkReachability
    :setCallback(hs.fnutils.partial(self.networkReachabilityCallback, self))
    :start()
  self:networkReachabilityCallback(nil, self.networkReachability:status())

  return self
end

--- DnssecDetector:stop()
--- Method
--- Stops the DnssecDetector spoon
function obj:stop()
  self.menubarItem:delete()
  self.networkConfiguration:stop()
  self.reachabilityConfiguration:stop()
end

--- DnssecDetector:getValue()
--- Method
--- Returns the network configuration value for given key and subkey
---
--- Parameters:
--- * key - the key specifing the content to retrieve from the store
--- * subkey - specifies the subkey to retrieve from within the content
---
--- Returns:
--- * the network configuration value
function obj:getValue(key, subkey)
  local content = self.networkConfiguration:contents(key)[key]
  if table.hasKey(content, subkey) then
    return content[subkey]
  else
    return nil
  end
end

--- DnssecDetector:networkReachabilityCallback()
--- Method
--- Fires whenever the internet is ()un)reachable and modified DNS name servers
---
--- Parameters:
--- * _ - ignored
--- * flags - the flags indicating (un)reachabiilty of the internet
function obj:networkReachabilityCallback(_, flags)
  self.logger.d("networkReachabilityCallback")

  local primaryService = self:getValue("State:/Network/Global/IPv4", "PrimaryService")
  if primaryService == nil then
    self.logger.d("no primary service")
    hs.notify.new()
      :title('DnssecDetector')
      :informativeText("no primary service")
      :send()
    return
  end

  local userDefinedName = self:getValue("Setup:/Network/Service/"..primaryService.."/Interface", "UserDefinedName")
  local serverAddresses = self:getValue("State:/Network/Service/"..primaryService.."/DNS", "ServerAddresses")
  local dnsResolverMode = nil

  -- detect tls-over-dns availability
  if dnsResolverMode == nil then
    local detectDnsOverTlsCommand = hs.spoons.resourcePath("detect-dns-over-tls")
    local detectDnsOverTlsResult = os.capture(detectDnsOverTlsCommand)
    if dnsResolverMode == nil and detectDnsOverTlsResult == "ERR" then
      self.logger.d("networkReachabilityCallbakck - detect-dns-over-tls broke")
      -- dnsResolverMode = nil --> fall through
    end
    if dnsResolverMode == nil and detectDnsOverTlsResult == "NAK" then
      self.logger.d("networkReachabilityCallback - dns-over-tls query failure")
      -- dnsResolverMode = nil --> fall through
    end
    if dnsResolverMode == nil and detectDnsOverTlsResult == "ACK" then
      self.logger.d("networkReachabilityCallback - dns-over-tls query success")
      dnsResolverMode = "Secure"
    end
  end

  -- detect captive portal existence
  if dnsResolverMode == nil then
    local detectCaptivePortalCommand = hs.spoons.resourcePath("detect-captive-portal").." "..table.concat(serverAddresses, ",")
    local detectCaptivePortalResult = os.capture(detectCaptivePortalCommand)
    if dnsResolverMode == nil and detectCaptivePortalResult == "ERR" then
      self.logger.d("networkReachabilityCallbakck - detect-captive-portal broke")
      -- dnsResolverMode = nil --> fall through
    end
    if dnsResolverMode == nil and detectCaptivePortal == "NAK" then
      self.logger.d("networkReachabilityCallbakck - unfriendly firewall detected")
      -- dnsResolverMode = nil --> fall through
    end
    if dnsResolverMode == nil and detectCaptivePortal == "ACK" then
      self.logger.d("networkReachabilityCallback = captive portal detected")
      dnsResolverMode = "Insecure"
    end
  end

  -- default dnsResolverMode
  if dnsResolverMode == nil then
    self.logger.d("networkReachabilityCallback = default resolver mode")
    dnsResolverMode = "Broken"
  end

  -- action the selected dnsResolverMode
  self.logger.d("networkReachabilityCallback - setting resolver mode to "..dnsResolverMode.." and flushing cache")
  if dnsResolverMode == "Secure" then
    self.logger.d("networkReachabilityCallback - use local unbound")
    os.execute("/usr/sbin/networksetup -setdnsservers "..userDefinedName.." 127.0.0.1")
  elseif dnsResolverMode == "Insecure" then
    self.logger.d("networkReachabilityCallback - use DHCP-provided dns servers")
    os.execute("/usr/sbin/networksetup -setdnsservers "..userDefinedName.." empty")
  elseif dnsResolverMode == "Broken" or dnsResolverMode == nil then
    self.logger.d("networkReachabilityCallback - prevent all lookups")
    os.execute("/usr/sbin/networksetup -setdnsservers "..userDefinedName.." 127.0.0.127")
  end
  os.execute("/usr/bin/dscacheutil -flushcache")
  hs.notify.new()
    :title('DnssecDetector')
    :informativeText("setting resolver mode to "..dnsResolverMode.." and flushing cache")
    :send()
end

--- DnssecDetector:networkConfigurationCallback()
--- Method
--- Fires whenever the DNS servers change and updates the menubar icon
---
--- Parameters:
--- * _ - ignored
--- * keys - the enumeration of keys that changed
function obj:networkConfigurationCallback(_, keys)
  self.logger.d("networkConfigurationCallback")
  local imageFile = hs.spoons.resourcePath("nak.png")
  local primaryService = self:getValue("State:/Network/Global/IPv4", "PrimaryService")
  if primaryService ~= nil then
    local serverAddresses = self:getValue("Setup:/Network/Service/"..primaryService.."/DNS", "ServerAddresses")
    if serverAddresses ~= nil and #serverAddresses == 1 and serverAddresses[1] == "127.0.0.1" then
      imageFile = hs.spoons.resourcePath("ack.png")
    end
  end
  self.menubarItem:setIcon(imageFile, false)
end

return obj
