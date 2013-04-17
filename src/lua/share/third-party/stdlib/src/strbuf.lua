--- String buffers

--- Create a new string buffer
local metatable = {}
local function new ()
  return setmetatable ({}, metatable)
end

--- Add a string to a buffer
-- @param b buffer
-- @param s string to add
-- @return buffer
local function concat (b, s)
  table.insert (b, s)
  return b
end

--- Convert a buffer to a string
-- @param b buffer
-- @return string
local function tostring (b)
  return table.concat (b)
end


-- Public interface
local M = {
  concat   = concat,
  new      = new,
  tostring = tostring,
}

--- Metamethods for string buffers
-- buffer:method ()
metatable.__index = M
-- buffer .. string
metatable.__concat = concat
-- tostring
metatable.__tostring = tostring

return M
