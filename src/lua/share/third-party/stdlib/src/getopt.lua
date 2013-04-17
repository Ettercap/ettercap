--- Simplified getopt, based on Svenne Panne's Haskell GetOpt.<br>
-- Usage:
-- <ul>
-- <li><code>prog = {<
--     name = <progname>,
--     [usage = <usage line>,]
--     [options = {
--        {{<name>[, ...]}, <desc>, [<type> [, <var>]]},
--        ...
--     },]
--     [banner = <banner string>,]
--     [purpose = <purpose string>,]
--     [notes = <additional notes>]
-- }</code></li>
-- <li>The <code>type</code> of option argument is one of <code>Req</code>(uired),
-- <code>Opt</code>(ional)</li>
-- <li>The <code>var</code>is a descriptive name for the option argument.</li>
-- <li><code>getopt.processArgs (prog)</code></li>
-- <li>Options take a single dash, but may have a double dash.</li>
-- <li>Arguments may be given as <code>-opt=arg</code> or <code>-opt arg</code>.</li>
-- <li>If an option taking an argument is given multiple times, only the
-- last value is returned; missing arguments are returned as 1.</li>
-- </ul>
-- getOpt, usageInfo and usage can be called directly (see
-- below, and the example at the end). Set _DEBUG.std to a non-nil
-- value to run the example.
-- <ul>
-- <li>TODO: Wrap all messages; do all wrapping in processArgs, not
-- usageInfo; use sdoc-like library (see string.format todos).</li>
-- <li>TODO: Don't require name to be repeated in banner.</li>
-- <li>TODO: Store version separately (construct banner?).</li>
-- </ul>

require "base"
local list = require "list"
require "string_ext"
local Object = require "object"

local M = {
  opt = {},
}


--- Perform argument processing
-- @param argIn list of command-line args
-- @param options options table
-- @param stop_at_nonopt if true, stop option processing at first non-option
-- @return table of remaining non-options
-- @return table of option key-value list pairs
-- @return table of error messages
local function getOpt (argIn, options, stop_at_nonopt)
  local noProcess = nil
  local argOut, optOut, errors = {[0] = argIn[0]}, {}, {}
  -- get an argument for option opt
  local function getArg (o, opt, arg, oldarg)
    if o.type == nil then
      if arg ~= nil then
        table.insert (errors, "option `" .. opt .. "' doesn't take an argument")
      end
    else
      if arg == nil and argIn[1] and
        string.sub (argIn[1], 1, 1) ~= "-" then
        arg = argIn[1]
        table.remove (argIn, 1)
      end
      if arg == nil and o.type == "Req" then
        table.insert (errors,  "option `" .. opt ..
                      "' requires an argument `" .. o.var .. "'")
        return nil
      end
    end
    return arg or 1 -- make sure arg has a value
  end

  local function parseOpt (opt, arg)
    local o = options.name[opt]
    if o ~= nil then
      o = o or {name = {opt}}
      optOut[o.name[1]] = optOut[o.name[1]] or {}
      table.insert (optOut[o.name[1]], getArg (o, opt, arg, optOut[o.name[1]]))
    else
      table.insert (errors, "unrecognized option `-" .. opt .. "'")
    end
  end
  while argIn[1] do
    local v = argIn[1]
    table.remove (argIn, 1)
    local _, _, dash, opt = string.find (v, "^(%-%-?)([^=-][^=]*)")
    local _, _, arg = string.find (v, "=(.*)$")
    if not dash and stop_at_nonopt then
      noProcess = true
    end
    if v == "--" then
      noProcess = true
    elseif not dash or noProcess then -- non-option
      table.insert (argOut, v)
    else -- option
      parseOpt (opt, arg)
    end
  end
  return argOut, optOut, errors
end


-- Object that defines a single Option entry.
local Option = Object {_init = {"name", "desc", "type", "var"}}

--- Options table constructor: adds lookup tables for the option names
local function makeOptions (t)
  local options, name = {}, {}
  local function appendOpt (v, nodupes)
    local dupe = false
    v = Option (v)
    for s in list.elems (v.name) do
      if name[s] then
	dupe = true
      end
      name[s] = v
    end
    if not dupe or nodupes ~= true then
      if dupe then warn ("duplicate option '%s'", s) end
      for s in list.elems (v.name) do name[s] = v end
      options = list.concat (options, {v})
    end
  end
  for v in list.elems (t or {}) do
    appendOpt (v)
  end
  -- Unless they were supplied already, add version and help options
  appendOpt ({{"version", "V"}, "print version information, then exit"},
             true)
  appendOpt ({{"help", "h"}, "print this help, then exit"}, true)
  options.name = name
  return options
end


--- Produce usage info for the given options
-- @param header header string
-- @param optDesc option descriptors
-- @param pageWidth width to format to [78]
-- @return formatted string
local function usageInfo (header, optDesc, pageWidth)
  pageWidth = pageWidth or 78
  -- Format the usage info for a single option
  -- @param opt the option table
  -- @return options
  -- @return description
  local function fmtOpt (opt)
    local function fmtName (o)
      return (#o > 1 and "--" or "-") .. o
    end
    local function fmtArg ()
      if opt.type == nil then
        return ""
      elseif opt.type == "Req" then
        return "=" .. opt.var
      else
        return "[=" .. opt.var .. "]"
      end
    end
    local textName = list.reverse (list.map (fmtName, opt.name))
    textName[#textName] = textName[#textName] .. fmtArg ()
    local indent = ""
    if #opt.name == 1 and #opt.name[1] > 1 then
      indent = "    "
    end
    return {indent .. table.concat ({table.concat (textName, ", ")}, ", "),
      opt.desc}
  end
  local function sameLen (xs)
    local n = math.max (unpack (list.map (string.len, xs)))
    for i, v in pairs (xs) do
      xs[i] = string.sub (v .. string.rep (" ", n), 1, n)
    end
    return xs, n
  end
  local function paste (x, y)
    return "  " .. x .. "  " .. y
  end
  local function wrapper (w, i)
    return function (s)
             return string.wrap (s, w, i, 0)
           end
  end
  local optText = ""
  if #optDesc > 0 then
    local cols = list.transpose (list.map (fmtOpt, optDesc))
    local width
    cols[1], width = sameLen (cols[1])
    cols[2] = list.map (wrapper (pageWidth, width + 4), cols[2])
    optText = "\n\n" ..
      table.concat (list.mapWith (paste,
                                  list.transpose ({sameLen (cols[1]),
                                                    cols[2]})),
                    "\n")
  end
  return header .. optText
end

--- Emit a usage message.
-- @param prog table of named parameters
local function usage (prog)
  local usage = "[OPTION]... [FILE]..."
  local purpose, description, notes = "", "", ""
  if prog.usage then
    usage = prog.usage
  end
  usage = "Usage: " .. prog.name .. " " .. usage
  if prog.purpose then
      purpose = "\n\n" .. prog.purpose
  end
  if prog.description then
    for para in list.elems (string.split (prog.description, "\n")) do
      description = description .. "\n\n" .. string.wrap (para)
    end
  end
  if prog.notes then
    notes = "\n\n"
    if not string.find (prog.notes, "\n") then
      notes = notes .. string.wrap (prog.notes)
    else
      notes = notes .. prog.notes
    end
  end
  local header = usage .. purpose .. description
  io.writelines (usageInfo (header, prog.options) .. notes)
end


local function version (prog)
  local version = prog.version or prog.name or "unknown version!"
  if prog.copyright then
    version = version .. "\n\n" .. prog.copyright
  end
  io.writelines (version)
end



--- Simple getOpt wrapper.
-- If the caller didn't supply their own already,
-- adds <code>--version</code>/<code>-V</code> and
-- <code>--help</code>/<code>-h</code> options automatically;
-- stops program if there was an error, or if <code>--help</code> or
-- <code>--version</code> was used.
-- @param prog table of named parameters
-- @param ... extra arguments for getOpt
local function processArgs (prog, ...)
  local totArgs = #_G.arg
  local errors
  prog.options = makeOptions (prog.options)
  _G.arg, M.opt, errors = getOpt (_G.arg, prog.options, ...)
  local opt = M.opt
  if (opt.version or opt.help) and prog.banner then
    io.writelines (prog.banner)
  end
  if #errors > 0 then
    local name = prog.name
    prog.name = nil
    if #errors > 0 then
      warn (name .. ": " .. table.concat (errors, "\n"))
      warn (name .. ": Try '" .. (arg[0] or name) .. " --help' for more help")
    end
    if #errors > 0 then
      error ()
    end
  elseif opt.version then
    version (prog)
  elseif opt.help then
    usage (prog)
  end
  if opt.version or opt.help then
    os.exit ()
  end
end


-- Public interface
return table.merge (M, {
  getOpt      = getOpt,
  processArgs = processArgs,
  usage       = usage,
  usageInfo   = usageInfo,
})
