--- Additions to the string module
-- TODO: Pretty printing (use in getopt); see source for details.

require "table_ext"
local list   = require "list"
local strbuf = require "strbuf"

-- Write pretty-printing based on:
--
--   John Hughes's and Simon Peyton Jones's Pretty Printer Combinators
--
--   Based on "The Design of a Pretty-printing Library in Advanced
--   Functional Programming", Johan Jeuring and Erik Meijer (eds), LNCS 925
--   http://www.cs.chalmers.se/~rjmh/Papers/pretty.ps
--   Heavily modified by Simon Peyton Jones, Dec 96
--
--   Haskell types:
--   data Doc     list of lines
--   quote :: Char -> Char -> Doc -> Doc    Wrap document in ...
--   (<>) :: Doc -> Doc -> Doc              Beside
--   (<+>) :: Doc -> Doc -> Doc             Beside, separated by space
--   ($$) :: Doc -> Doc -> Doc              Above; if there is no overlap it "dovetails" the two
--   nest :: Int -> Doc -> Doc              Nested
--   punctuate :: Doc -> [Doc] -> [Doc]     punctuate p [d1, ... dn] = [d1 <> p, d2 <> p, ... dn-1 <> p, dn]
--   render      :: Int                     Line length
--               -> Float                   Ribbons per line
--               -> (TextDetails -> a -> a) What to do with text
--               -> a                       What to do at the end
--               -> Doc                     The document
--               -> a                       Result


--- Give strings a subscription operator.
-- @param s string
-- @param i index
-- @return <code>string.sub (s, i, i)</code> if i is a number, or
-- falls back to any previous metamethod (by default, string methods)
local old__index = getmetatable ("").__index
getmetatable ("").__index = function (s, i)
  if type (i) == "number" then
    return s:sub (i, i)
    -- Fall back to old metamethods
  elseif type (old__index) == "function" then
    return old__index (s, i)
  else
    return old__index[i]
  end
end

--- Give strings an append metamethod.
-- @param s string
-- @param c character (1-character string)
-- @return <code>s .. c</code>
getmetatable ("").__append = function (s, c)
  return s .. c
end

--- Give strings a concat metamethod.
-- @param s string
-- @param o object
-- @return s .. tostring (o)
getmetatable ("").__concat = function (s, o)
  return tostring (s) .. tostring (o)
end

--- Capitalise each word in a string.
-- @param s string
-- @return capitalised string
local function caps (s)
  return (string.gsub (s, "(%w)([%w]*)",
                      function (l, ls)
                        return string.upper (l) .. ls
                      end))
end

--- Remove any final newline from a string.
-- @param s string to process
-- @return processed string
local function chomp (s)
  return (string.gsub (s, "\n$", ""))
end

--- Escape a string to be used as a pattern
-- @param s string to process
-- @return
--   @param s_: processed string
local function escape_pattern (s)
  return (string.gsub (s, "(%W)", "%%%1"))
end

-- Escape a string to be used as a shell token.
-- Quotes spaces, parentheses, brackets, quotes, apostrophes and
-- whitespace.
-- @param s string to process
-- @return processed string
local function escape_shell (s)
  return (string.gsub (s, "([ %(%)%\\%[%]\"'])", "\\%1"))
end

--- Return the English suffix for an ordinal.
-- @param n number of the day
-- @return suffix
local function ordinal_suffix (n)
  n = math.abs (n) % 100
  local d = n % 10
  if d == 1 and n ~= 11 then
    return "st"
  elseif d == 2 and n ~= 12 then
    return "nd"
  elseif d == 3 and n ~= 13 then
    return "rd"
  else
    return "th"
  end
end

--- Extend to work better with one argument.
-- If only one argument is passed, no formatting is attempted.
-- @param f format
-- @param ... arguments to format
-- @return formatted string
local _format = string.format
local function format (f, arg1, ...)
  if arg1 == nil then
    return f
  else
    return _format (f, arg1, ...)
  end
end

--- Justify a string.
-- When the string is longer than w, it is truncated (left or right
-- according to the sign of w).
-- @param s string to justify
-- @param w width to justify to (-ve means right-justify; +ve means
-- left-justify)
-- @param p string to pad with (default: <code>" "</code>)
-- @return justified string
local function pad (s, w, p)
  p = string.rep (p or " ", math.abs (w))
  if w < 0 then
    return string.sub (p .. s, w)
  end
  return string.sub (s .. p, 1, w)
end

--- Wrap a string into a paragraph.
-- @param s string to wrap
-- @param w width to wrap to (default: 78)
-- @param ind indent (default: 0)
-- @param ind1 indent of first line (default: ind)
-- @return wrapped paragraph
local function wrap (s, w, ind, ind1)
  w = w or 78
  ind = ind or 0
  ind1 = ind1 or ind
  assert (ind1 < w and ind < w,
          "the indents must be less than the line width")
  assert (type (s) == "string",
          "bad argument #1 to 'wrap' (string expected, got " .. type (s) .. ")")
  local r = strbuf.new ():concat (string.rep (" ", ind1))
  local i, lstart, len = 1, ind1, #s
  while i <= #s do
    local j = i + w - lstart
    while #s[j] > 0 and s[j] ~= " " and j > i do
      j = j - 1
    end
    local ni = j + 1
    while s[j] == " " do
      j = j - 1
    end
    r:concat (s:sub (i, j))
    i = ni
    if i < #s then
      r:concat ("\n" .. string.rep (" ", ind))
      lstart = ind
    end
  end
  return r:tostring ()
end

--- Write a number using SI suffixes.
-- The number is always written to 3 s.f.
-- @param n number
-- @return string
local function numbertosi (n)
  local SIprefix = {
    [-8] = "y", [-7] = "z", [-6] = "a", [-5] = "f",
    [-4] = "p", [-3] = "n", [-2] = "mu", [-1] = "m",
    [0] = "", [1] = "k", [2] = "M", [3] = "G",
    [4] = "T", [5] = "P", [6] = "E", [7] = "Z",
    [8] = "Y"
  }
  local t = string.format("% #.2e", n)
  local _, _, m, e = t:find(".(.%...)e(.+)")
  local man, exp = tonumber (m), tonumber (e)
  local siexp = math.floor (exp / 3)
  local shift = exp - siexp * 3
  local s = SIprefix[siexp] or "e" .. tostring (siexp)
  man = man * (10 ^ shift)
  return tostring (man) .. s
end

--- Do find, returning captures as a list.
-- @param s target string
-- @param p pattern
-- @param init start position (default: 1)
-- @param plain inhibit magic characters (default: nil)
-- @return start of match, end of match, table of captures
local function tfind (s, p, init, plain)
  assert (type (s) == "string",
          "bad argument #1 to 'tfind' (string expected, got " .. type (s) .. ")")
  assert (type (p) == "string",
          "bad argument #2 to 'tfind' (string expected, got " .. type (p) .. ")")
  local function pack (from, to, ...)
    return from, to, {...}
  end
  return pack (p.find (s, p, init, plain))
end

--- Do multiple <code>find</code>s on a string.
-- @param s target string
-- @param p pattern
-- @param init start position (default: 1)
-- @param plain inhibit magic characters (default: nil)
-- @return list of <code>{from, to; capt = {captures}}</code>
local function finds (s, p, init, plain)
  init = init or 1
  local l = {}
  local from, to, r
  repeat
    from, to, r = tfind (s, p, init, plain)
    if from ~= nil then
      table.insert (l, {from, to, capt = r})
      init = to + 1
    end
  until not from
  return l
end

--- Split a string at a given separator.
-- FIXME: Consider Perl and Python versions.
-- @param s string to split
-- @param sep separator pattern
-- @return list of strings
local function split (s, sep)
  -- finds gets a list of {from, to, capt = {}} lists; we then
  -- flatten the result, discarding the captures, and prepend 0 (1
  -- before the first character) and append 0 (1 after the last
  -- character), and then read off the result in pairs.
  local pairs = list.concat ({0}, list.flatten (finds (s, sep)), {0})
  local l = {}
  for i = 1, #pairs, 2 do
    table.insert (l, string.sub (s, pairs[i] + 1, pairs[i + 1] - 1))
  end
  return l
end

--- Remove leading matter from a string.
-- @param s string
-- @param r leading pattern (default: <code>"%s+"</code>)
-- @return string without leading r
local function ltrim (s, r)
  r = r or "%s+"
  return (string.gsub (s, "^" .. r, ""))
end

--- Remove trailing matter from a string.
-- @param s string
-- @param r trailing pattern (default: <code>"%s+"</code>)
-- @return string without trailing r
local function rtrim (s, r)
  r = r or "%s+"
  return (string.gsub (s, r .. "$", ""))
end

--- Remove leading and trailing matter from a string.
-- @param s string
-- @param r leading/trailing pattern (default: <code>"%s+"</code>)
-- @return string without leading/trailing r
local function trim (s, r)
  return rtrim (ltrim (s, r), r)
end

-- Save original unextended table.
local unextended = table.clone (string)

local M = {
  __index        = old__index,
  caps           = caps,
  chomp          = chomp,
  escape_pattern = escape_pattern,
  escape_shell   = escape_shell,
  finds          = finds,
  format         = format,
  ltrim          = ltrim,
  numbertosi     = numbertosi,
  ordinal_suffix = ordinal_suffix,
  pad            = pad,
  rtrim          = rtrim,
  split          = split,
  tfind          = tfind,
  trim           = trim,
  wrap           = wrap,

  -- camelCase compatibility:
  escapePattern  = escape_pattern,
  escapeShell    = escape_shell,
  ordinalSuffix  = ordinal_suffix,
}

-- Inject stdlib extensions directly into the string package.
_G.string = table.merge (string, M)

return unextended
