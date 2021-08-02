# DnssecDetector.spoon

This is a replacement for [dnssec-trigger][1] that leverages [hammerspoon][2].

The solution makes use of [MacPorts][3]' unbound, knot (kdig), curl-ca-bundle,
curl (+ares +http2 +ssl), and bash. Included in this repository is an example
`unbound.conf` that only uses DNS-over-TLS.

Other than the two image files, the source files are copyright Luca Filipozzi
under a BSD 3-clause license.

The two image files are copyright NLnet Labs under a BSD 3-clause license.

Please note that this solution relies on two utility functions added to
`~/.hammerspoon/init.lua`:

```lua
function os.capture(cmd, raw)
  local f = assert(io.popen(cmd, 'r'))
  local s = assert(f:read('*a'))
  f:close()
  if raw then return s end
  s = string.gsub(s, '^%s+', '')
  s = string.gsub(s, '%s+$', '')
  s = string.gsub(s, '[\n\r]+', ' ')
  return s
end
```

and

```lua
function table.hasKey(tbl, key)
  return tbl ~= nil and tbl[key] ~= nil
end
```

Triggering a _reprobe_ is possible via a hotkey binding added to
`~/.hammerspoon/init.lua`:

```lua
hs.loadSpoon("DnssecDetector")
spoon.DnssecDetector:start()
local callback = hs.fnutils.partial(
  spoon.DnssecDetector.networkReachabilityCallback,
  spoon.DnssecDetector,
  nil,
  hs.network.reachability.internet():status())
hs.hotkey.bind({"cmd", "alt", "ctrl"}, "W", callback)
```

[1]: https://github.com/NLnetLabs/dnssec-trigger
[2]: https://github.com/Hammerspoon/hammerspoon
[3]: https://www.macports.org/
