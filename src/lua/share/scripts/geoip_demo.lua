---

description = [[ This demonstrates the use of GeoIP information in Ettercap.
                 For this script to work, Ettercap MUST have been compiled
                 with '-DHAVE_GEOIP', which is set by the cmake user option
                 ENABLE_GEOIP (ON by default).
              ]]

local ffi         = require ('ettercap_ffi')
local packet      = require ("packet")
local hook_points = require ("hook_points")

-- Hook at the filtering point
--
hook_point = hook_points.filter

is_ip = function(p)
  return (p.L3 and (p.L3.proto == 0x8 or p.L3.proto == 0xDD86))
end

-- Optional, but we only want to look at IP-packets.
--
packetrule = function (p)
  if not is_ip(p) then
    -- ettercap.log ("Ignoring non IP-packet: %d.\n", p.L3.proto)
    return false
  end
  return true
end

-- Here's your action.
--
action = function (p)

  tstamp = os.date ("%X", p.ts.tv_sec) .. string.format (".%06d", p.ts.tv_usec)

  src = string.format ("%s:%d", packet.src_ip(p), packet.src_port(p))
  dst = string.format ("%s:%d", packet.dst_ip(p), packet.dst_port(p))
  src_c = ffi.string (ffi.C.geoip_ccode_by_ip(p.L3.src))
  dst_c = ffi.string (ffi.C.geoip_ccode_by_ip(p.L3.dst))

  ettercap.log("%s: %-20s -> %-20s: %s -> %s", tstamp, src, dst, src_c, dst_c)
end
