--- Tables as lists.
require "base"

local new  -- forward declaration

--- An iterator over the elements of a list.
-- @param l list to iterate over
-- @return iterator function which returns successive elements of the list
-- @return the list <code>l</code> as above
-- @return <code>true</code>
local function elems (l)
  local n = 0
  return function (l)
           n = n + 1
           if n <= #l then
             return l[n]
           end
         end,
  l, true
end

--- An iterator over the elements of a list, in reverse.
-- @param l list to iterate over
-- @return iterator function which returns precessive elements of the list
-- @return the list <code>l</code> as above
-- @return <code>true</code>
local function relems (l)
  local n = #l + 1
  return function (l)
           n = n - 1
           if n > 0 then
             return l[n]
           end
         end,
  l, true
end

--- Map a function over a list.
-- @param f function
-- @param l list
-- @return result list <code>{f (l[1]), ..., f (l[#l])}</code>
local function map (f, l)
  return _G.map (f, elems, l)
end

--- Map a function over a list of lists.
-- @param f function
-- @param ls list of lists
-- @return result list <code>{f (unpack (ls[1]))), ..., f (unpack (ls[#ls]))}</code>
local function mapWith (f, l)
  return _G.map (compose (f, unpack), elems, l)
end

--- Filter a list according to a predicate.
-- @param p predicate (function of one argument returning a boolean)
-- @param l list of lists
-- @return result list containing elements <code>e</code> of
--   <code>l</code> for which <code>p (e)</code> is true
local function filter (p, l)
  return _G.filter (p, elems, l)
end

--- Return a sub-range of a list. (The equivalent of <code>string.sub</code>
-- on strings; negative list indices count from the end of the list.)
-- @param l list
-- @param from start of range (default: 1)
-- @param to end of range (default: <code>#l</code>)
-- @return <code>{l[from], ..., l[to]}</code>
local function sub (l, from, to)
  local r = new ()
  local len = #l
  from = from or 1
  to = to or len
  if from < 0 then
    from = from + len + 1
  end
  if to < 0 then
    to = to + len + 1
  end
  for i = from, to do
    table.insert (r, l[i])
  end
  return r
end

--- Return a list with its first element removed.
-- @param l list
-- @return <code>{l[2], ..., l[#l]}</code>
local function tail (l)
  return sub (l, 2)
end

--- Fold a binary function through a list left associatively.
-- @param f function
-- @param e element to place in left-most position
-- @param l list
-- @return result
local function foldl (f, e, l)
  return fold (f, e, elems, l)
end

--- Fold a binary function through a list right associatively.
-- @param f function
-- @param e element to place in right-most position
-- @param l list
-- @return result
local function foldr (f, e, l)
  return fold (function (x, y) return f (y, x) end,
               e, relems, l)
end

--- Prepend an item to a list.
-- @param l list
-- @param x item
-- @return <code>{x, unpack (l)}</code>
local function cons (l, x)
  return {x, unpack (l)}
end

--- Append an item to a list.
-- @param l list
-- @param x item
-- @return <code>{l[1], ..., l[#l], x}</code>
local function append (l, x)
  local r = {unpack (l)}
  table.insert (r, x)
  return r
end

--- Concatenate lists.
-- @param ... lists
-- @return <code>{l<sub>1</sub>[1], ...,
-- l<sub>1</sub>[#l<sub>1</sub>], ..., l<sub>n</sub>[1], ...,
-- l<sub>n</sub>[#l<sub>n</sub>]}</code>
local function concat (...)
  local r = new ()
  for l in elems ({...}) do
    for v in elems (l) do
      table.insert (r, v)
    end
  end
  return r
end

--- Repeat a list.
-- @param l list
-- @param n number of times to repeat
-- @return <code>n</code> copies of <code>l</code> appended together
local function rep (l, n)
  local r = new ()
  for i = 1, n do
    r = concat (r, l)
  end
  return r
end

--- Reverse a list.
-- @param l list
-- @return list <code>{l[#l], ..., l[1]}</code>
local function reverse (l)
  local r = new ()
  for i = #l, 1, -1 do
    table.insert (r, l[i])
  end
  return r
end

--- Transpose a list of lists.
-- This function in Lua is equivalent to zip and unzip in more
-- strongly typed languages.
-- @param ls <code>{{l<sub>1,1</sub>, ..., l<sub>1,c</sub>}, ...,
-- {l<sub>r,1<sub>, ..., l<sub>r,c</sub>}}</code>
-- @return <code>{{l<sub>1,1</sub>, ..., l<sub>r,1</sub>}, ...,
-- {l<sub>1,c</sub>, ..., l<sub>r,c</sub>}}</code>
local function transpose (ls)
  local rs, len = new (), #ls
  for i = 1, math.max (unpack (map (function (l) return #l end, ls))) do
    rs[i] = new ()
    for j = 1, len do
      rs[i][j] = ls[j][i]
    end
  end
  return rs
end

--- Zip lists together with a function.
-- @param f function
-- @param ls list of lists
-- @return <code>{f (ls[1][1], ..., ls[#ls][1]), ..., f (ls[1][N], ..., ls[#ls][N])</code>
-- where <code>N = max {map (function (l) return #l end, ls)}</code>
local function zipWith (f, ls)
  return mapWith (f, transpose (ls))
end

--- Project a list of fields from a list of tables.
-- @param f field to project
-- @param l list of tables
-- @return list of <code>f</code> fields
local function project (f, l)
  return map (function (t) return t[f] end, l)
end

--- Turn a table into a list of pairs.
-- <br>FIXME: Find a better name.
-- @param t table <code>{i<sub>1</sub>=v<sub>1</sub>, ...,
-- i<sub>n</sub>=v<sub>n</sub>}</code>
-- @return list <code>{{i<sub>1</sub>, v<sub>1</sub>}, ...,
-- {i<sub>n</sub>, v<sub>n</sub>}}</code>
local function enpair (t)
  local ls = new ()
  for i, v in pairs (t) do
    table.insert (ls, {i, v})
  end
  return ls
end

--- Turn a list of pairs into a table.
-- <br>FIXME: Find a better name.
-- @param ls list <code>{{i<sub>1</sub>, v<sub>1</sub>}, ...,
-- {i<sub>n</sub>, v<sub>n</sub>}}</code>
-- @return table <code>{i<sub>1</sub>=v<sub>1</sub>, ...,
-- i<sub>n</sub>=v<sub>n</sub>}</code>
local function depair (ls)
  local t = {}
  for v in elems (ls) do
    t[v[1]] = v[2]
  end
  return t
end

--- Flatten a list.
-- @param l list to flatten
-- @return flattened list
local function flatten (l)
  local r = new ()
  for v in ileaves (l) do
    table.insert (r, v)
  end
  return r
end

--- Shape a list according to a list of dimensions.
--
-- Dimensions are given outermost first and items from the original
-- list are distributed breadth first; there may be one 0 indicating
-- an indefinite number. Hence, <code>{0}</code> is a flat list,
-- <code>{1}</code> is a singleton, <code>{2, 0}</code> is a list of
-- two lists, and <code>{0, 2}</code> is a list of pairs.
-- <br>
-- Algorithm: turn shape into all positive numbers, calculating
-- the zero if necessary and making sure there is at most one;
-- recursively walk the shape, adding empty tables until the bottom
-- level is reached at which point add table items instead, using a
-- counter to walk the flattened original list.
-- <br>
-- @param s <code>{d<sub>1</sub>, ..., d<sub>n</sub>}</code>
-- @param l list to reshape
-- @return reshaped list
-- FIXME: Use ileaves instead of flatten (needs a while instead of a
-- for in fill function)
local function shape (s, l)
  l = flatten (l)
  -- Check the shape and calculate the size of the zero, if any
  local size = 1
  local zero
  for i, v in ipairs (s) do
    if v == 0 then
      if zero then -- bad shape: two zeros
        return nil
      else
        zero = i
      end
    else
      size = size * v
    end
  end
  if zero then
    s[zero] = math.ceil (#l / size)
  end
  local function fill (i, d)
    if d > #s then
      return l[i], i + 1
    else
      local r = new ()
      for j = 1, s[d] do
        local e
        e, i = fill (i, d + 1)
        table.insert (r, e)
      end
      return r, i
    end
  end
  return (fill (1, 1))
end

--- Make an index of a list of tables on a given field
-- @param f field
-- @param l list of tables <code>{t<sub>1</sub>, ...,
-- t<sub>n</sub>}</code>
-- @return index <code>{t<sub>1</sub>[f]=1, ...,
-- t<sub>n</sub>[f]=n}</code>
local function indexKey (f, l)
  local r = new ()
  for i, v in ipairs (l) do
    local k = v[f]
    if k then
      r[k] = i
    end
  end
  return r
end

--- Copy a list of tables, indexed on a given field
-- @param f field whose value should be used as index
-- @param l list of tables <code>{i<sub>1</sub>=t<sub>1</sub>, ...,
-- i<sub>n</sub>=t<sub>n</sub>}</code>
-- @return index <code>{t<sub>1</sub>[f]=t<sub>1</sub>, ...,
-- t<sub>n</sub>[f]=t<sub>n</sub>}</code>
local function indexValue (f, l)
  local r = new ()
  for i, v in ipairs (l) do
    local k = v[f]
    if k then
      r[k] = v
    end
  end
  return r
end
permuteOn = indexValue

--- Compare two lists element by element left-to-right
-- @param l first list
-- @param m second list
-- @return -1 if <code>l</code> is less than <code>m</code>, 0 if they
-- are the same, and 1 if <code>l</code> is greater than <code>m</code>
local function compare (l, m)
  for i = 1, math.min (#l, #m) do
    if l[i] < m[i] then
      return -1
    elseif l[i] > m[i] then
      return 1
    end
  end
  if #l < #m then
    return -1
  elseif #l > #m then
    return 1
  end
  return 0
end

-- Methods for lists
local methods = {
  append     = append,
  compare    = compare,
  concat     = concat,
  cons       = cons,
  depair     = depair,
  elems      = elems,
  filter     = function (self, p) return filter (p, self) end,
  flatten    = flatten,
  foldl      = function (self, f, e) return foldl (f, e, self) end,
  foldr      = function (self, f, e) return foldr (f, e, self) end,
  indexKey   = function (self, f) return indexKey (self, f) end,
  indexValue = function (self, f) return indexValue (self, f) end,
  map        = function (self, f) return map (f, self) end,
  mapWith    = function (self, f) return mapWith (f, self) end,
  project    = function (self, f) return project (f, self) end,
  relems     = relems,
  rep        = rep,
  reverse    = reverse,
  shape      = function (self, s) return shape (s, self) end,
  sub        = sub,
  tail       = tail,
  transpose  = transpose,
  zipWith    = function (self, f) return zipWith (f, self) end,
}

-- Metamethods for lists
local metatable = {
  -- list .. table = list.concat
  __concat = concat,
  -- list == list retains its referential meaning
  -- list < list = list.compare returns < 0
  __lt = function (l, m) return compare (l, m) < 0 end,
  -- list <= list = list.compare returns <= 0
  __le = function (l, m) return compare (l, m) <= 0 end,
  __append = append,
  __index = methods,
}

--- List constructor.
-- Needed in order to use metamethods.
-- @param t list (as a table), or nil for empty list
-- @return list (with list metamethods)
function new (l)
  return setmetatable (l or {}, metatable)
end

-- Function forms of operators
_G.op[".."] = concat

-- Public interface
local M = {
  append     = append,
  compare    = compare,
  concat     = concat,
  cons       = cons,
  depair     = depair,
  elems      = elems,
  enpair     = enpair,
  filter     = filter,
  flatten    = flatten,
  foldl      = foldl,
  foldr      = foldr,
  indexKey   = indexKey,
  indexValue = indexValue,
  new        = new,
  map        = map,
  mapWith    = mapWith,
  project    = project,
  relems     = relems,
  rep        = rep,
  reverse    = reverse,
  shape      = shape,
  slice      = sub, -- backwards compatibility
  sub        = sub,
  tail       = tail,
  transpose  = transpose,
  zipWith    = zipWith,
}

return M
