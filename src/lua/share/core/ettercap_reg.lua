--- This provides a very simple registry 
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

--

local ettercap_registry = {}

--- Indicates if we have a namespace, or not.
-- @return true or false, depending on if we have a workspace or not.
workspace_exists = function(ns)
  return (not (ettercap_registry[ns] == nil))
end

--- Creates a namespace if it does not already exist, and then returns it.
-- @param ns 
-- @return A table
create_namespace = function(ns)
  local ret = ettercap_registry[ns]
  if ret == nil then
    ret = {}
    ettercap_registry[ns] = ret
  end
  return ret
end

--- Retreives a namespace. Returns nil if the namespace doesn't exist.
-- @param ns
-- @return A table, or nil
get_namespace = function(ns)
  -- Doesn't matter if it exists or not. It's either nil or not, so we just
  -- return.
  return ettercap_registry[ns]
end

--- Delete's a namespace, effectively. 
-- @param ns
delete_namespace = function(ns)
  -- Fun fact, if you set a table entry to nil, it deletes the key as well.
  ettercap_registry[ns] = nil
end

local reg = {}
reg.workspace_exists = workspace_exists
reg.create_namespace = create_namespace
reg.get_namespace = get_namespace
reg.delete_namespace = delete_namespace
return reg
