-- Extensions to the table module

--local list = require "list" FIXME: allow require loops


local _sort = table.sort
--- Make table.sort return its result.
-- @param t table
-- @param c comparator function
-- @return sorted table
local function sort (t, c)
  _sort (t, c)
  return t
end

--- Return whether table is empty.
-- @param t table
-- @return <code>true</code> if empty or <code>false</code> otherwise
local function empty (t)
  return not next (t)
end

--- Find the number of elements in a table.
-- @param t table
-- @return number of elements in t
local function size (t)
  local n = 0
  for _ in pairs (t) do
    n = n + 1
  end
  return n
end

--- Make the list of keys of a table.
-- @param t table
-- @return list of keys
local function keys (t)
  local u = {}
  for i, v in pairs (t) do
    table.insert (u, i)
  end
  return u
end

--- Make the list of values of a table.
-- @param t table
-- @return list of values
local function values (t)
  local u = {}
  for i, v in pairs (t) do
    table.insert (u, v)
  end
  return u
end

--- Invert a table.
-- @param t table <code>{i=v, ...}</code>
-- @return inverted table <code>{v=i, ...}</code>
local function invert (t)
  local u = {}
  for i, v in pairs (t) do
    u[v] = i
  end
  return u
end

--- Make a shallow copy of a table, including any metatable (for a
-- deep copy, use tree.clone).
-- @param t table
-- @param nometa if non-nil don't copy metatable
-- @return copy of table
local function clone (t, nometa)
  local u = {}
  if not nometa then
    setmetatable (u, getmetatable (t))
  end
  for i, v in pairs (t) do
    u[i] = v
  end
  return u
end

--- Clone a table, renaming some keys.
-- @param map table <code>{old_key=new_key, ...}</code>
-- @param t table to copy
-- @return copy of table
local function clone_rename (map, t)
  local r = clone (t)
  for i, v in pairs (map) do
    r[v] = t[i]
    r[i] = nil
  end
  return r
end

--- Merge one table into another. <code>u</code> is merged into <code>t</code>.
-- @param t first table
-- @param u second table
-- @return first table
local function merge (t, u)
  for i, v in pairs (u) do
    t[i] = v
  end
  return t
end

--- Make a table with a default value for unset keys.
-- @param x default entry value (default: <code>nil</code>)
-- @param t initial table (default: <code>{}</code>)
-- @return table whose unset elements are x
local function new (x, t)
  return setmetatable (t or {},
                       {__index = function (t, i)
                                    return x
                                  end})
end

-- Save original unextended table.
local unextended = clone (table)

local M = {
  clone        = clone,
  clone_rename = clone_rename,
  empty        = empty,
  invert       = invert,
  keys         = keys,
  merge        = merge,
  new          = new,
  size         = size,
  sort         = sort,
  values       = values,
}

-- Inject stdlib extensions directly into the table package.
_G.table = merge (table, M)

return unextended
