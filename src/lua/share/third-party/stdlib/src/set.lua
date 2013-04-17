local list = require "list"


-- Primitive methods (know about representation)
-- The representation is a table whose tags are the elements, and
-- whose values are true.

--- Say whether an element is in a set
-- @param s set
-- @param e element
-- @return <code>true</code> if e is in set, <code>false</code>
-- otherwise
local function member (s, e)
  return rawget (s.contents, e) == true
end

--- Insert an element into a set
-- @param s set
-- @param e element
local function insert (s, e)
  rawset (s.contents, e, true)
end

--- Delete an element from a set
-- @param s set
-- @param e element
local function delete (s, e)
  rawset (s.contents, e, nil)
end

--- Make a list into a set
-- @param l list
-- @return set
local metatable = {}
local function new (l)
  local s = setmetatable ({contents={}}, metatable)
  for e in list.elems (l) do
    insert (s, e)
  end
  return s
end

--- Iterator for sets
-- TODO: Make the iterator return only the key
local function elems (s)
  return pairs (s.contents)
end


-- High level methods (representation-independent)

local difference, symmetric_difference, intersection, union, subset, equal

--- Find the difference of two sets
-- @param s set
-- @param t set
-- @return s with elements of t removed
function difference (s, t)
  local r = new {}
  for e in elems (s) do
    if not member (t, e) then
      insert (r, e)
    end
  end
  return r
end

--- Find the symmetric difference of two sets
-- @param s set
-- @param t set
-- @return elements of s and t that are in s or t but not both
function symmetric_difference (s, t)
  return difference (union (s, t), intersection (t, s))
end

--- Find the intersection of two sets
-- @param s set
-- @param t set
-- @return set intersection of s and t
function intersection (s, t)
  local r = new {}
  for e in elems (s) do
    if member (t, e) then
      insert (r, e)
    end
  end
  return r
end

--- Find the union of two sets
-- @param s set
-- @param t set
-- @return set union of s and t
function union (s, t)
  local r = new {}
  for e in elems (s) do
    insert (r, e)
  end
  for e in elems (t) do
    insert (r, e)
  end
  return r
end

--- Find whether one set is a subset of another
-- @param s set
-- @param t set
-- @return <code>true</code> if s is a subset of t, <code>false</code>
-- otherwise
function subset (s, t)
  for e in elems (s) do
    if not member (t, e) then
      return false
    end
  end
  return true
end

--- Find whether one set is a proper subset of another
-- @param s set
-- @param t set
-- @return <code>true</code> if s is a proper subset of t, false otherwise
function propersubset (s, t)
  return subset (s, t) and not subset (t, s)
end

--- Find whether two sets are equal
-- @param s set
-- @param t set
-- @return <code>true</code> if sets are equal, <code>false</code>
-- otherwise
function equal (s, t)
  return subset (s, t) and subset (t, s)
end

-- Public interface
local M = {
  delete       = delete,
  difference   = difference,
  elems        = elems,
  equal        = equal,
  insert       = insert,
  intersection = intersection,
  member       = member,
  new          = new,
  subset       = subset,
  symmetric_difference = symmetric_difference,
  union        = union,
}

--- Metamethods for sets
-- set:method ()
metatable.__index = M
-- set + table = union
metatable.__add = union
-- set - table = set difference
metatable.__sub = difference
-- set * table = intersection
metatable.__mul = intersection
-- set / table = symmetric difference
metatable.__div = symmetric_difference
-- set <= table = subset
metatable.__le = subset
-- set < table = proper subset
metatable.__lt = propersubset

return M
