--- 
-- The purpose of this lib is to provide a simple way of defining the style of 
-- session tracking that would be employed by a given script.

local ffi = require("ettercap_ffi")

local shortsession = {}

-- We need the size of a pointer so that we know how to address things properly.
local ptr_size = ffi.sizeof("void *")

local ident_magic_ptr = ffi.typeof("struct ident_magic *")

-- Search down through the session structures for either an IP or IPv6 
-- session object. If we find that, then use it. If we don't find the session
-- structure, then return nil.
--
-- @return string (on success) or nil (on failure)
ip_session = function(packet_object)
  local session = packet_object.session
  while true do
    if not session then
      return nil
    end
    local ident = session.ident
    if ident then
      local ident_magic = ffi.cast(ident_magic_ptr, ident)
      local magic = tonumber(ident_magic.magic)
      -- If we've found an IP or IP6 magic, then break.
      if magic == ffi.C.IP_MAGIC then
        break
      elseif magic == ffi.C.IP6_MAGIC then
        break
      end
    end

    -- go to the next session in the chain...
    session = session.prev_session
  end

  -- If we've gotten here, then we've found a session.
  ip_sess_memory_addr = ffi.string(session, ptr_size)
  return(table.concat({"inject_http", ip_sess_memory_addr}, "-"))
end

shortsession.ip_session = ip_session

return shortsession
