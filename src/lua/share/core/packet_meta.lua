--- Adds packet methods directly to packet_object ctype
--
--    Copyright (C) Ryan Linn and Mike Ryan
--
--    This program is free software; you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation; either version 2 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program; if not, write to the Free Software
--    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

ffi = require('ettercap_ffi')
packet = require('packet')

local po_mt = {
  __index = {
    has_data = function(po) return packet.has_data(po) end,
    is_tcp = function(po) return packet.is_tcp(po) end,
    is_udp = function(po) return packet.is_udp(po) end,
    read_data = function(po, length) return packet.read_data(po, length) end,
    set_modified = function(po) return packet.set_modified(po) end,
    set_data = function(po, data) return packet.set_data(po, data) end,
    src_ip = function(po) return packet.src_ip(po) end,
    dst_ip = function(po) return packet.dst_ip(po) end,
    src_port = function(po) return packet.src_port(po) end,
    dst_port = function(po) return packet.dst_port(po) end,
  }
}

ffi.metatype("struct packet_object", po_mt)

return nil
