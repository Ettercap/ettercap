--- Additions to the io module
module ("io", package.seeall)

require "base"
local package_unext = require "package_ext"


-- Get file handle metatable
local file_metatable = getmetatable (io.stdin)


-- Get an input file handle.
-- @param h file handle or name (default: <code>io.input ()</code>)
-- @return file handle, or nil on error
local function input_handle (h)
  if h == nil then
    h = input ()
  elseif _G.type (h) == "string" then
    h = io.open (h)
  end
  return h
end

--- Slurp a file handle.
-- @param h file handle or name (default: <code>io.input ()</code>)
-- @return contents of file or handle, or nil if error
function slurp (h)
  h = input_handle (h)
  if h then
    local s = h:read ("*a")
    h:close ()
    return s
  end
end

--- Read a file or file handle into a list of lines.
-- @param h file handle or name (default: <code>io.input ()</code>);
-- if h is a handle, the file is closed after reading
-- @return list of lines
function readlines (h)
  h = input_handle (h)
  local l = {}
  for line in h:lines () do
    table.insert (l, line)
  end
  h:close ()
  return l
end
file_metatable.readlines = readlines

--- Write values adding a newline after each.
-- @param h file handle (default: <code>io.output ()</code>
-- @param ... values to write (as for write)
function writelines (h, ...)
  if io.type (h) ~= "file" then
    io.write (h, "\n")
    h = io.output ()
  end
  for v in ileaves ({...}) do
    h:write (v, "\n")
  end
end
file_metatable.writelines = writelines

--- Split a directory path into components.
-- Empty components are retained: the root directory becomes <code>{"", ""}</code>.
-- @param path path
-- @return list of path components
function splitdir (path)
  return string.split (path, package.dirsep)
end

--- Concatenate one or more directories and a filename into a path.
-- @param ... path components
-- @return path
function catfile (...)
  return table.concat ({...}, package.dirsep)
end

--- Concatenate two or more directories into a path, removing the trailing slash.
-- @param ... path components
-- @return path
function catdir (...)
  return (string.gsub (catfile (...), "^$", package.dirsep))
end

--- Perform a shell command and return its output.
-- @param c command
-- @return output, or nil if error
function shell (c)
  return io.slurp (io.popen (c))
end

--- Process files specified on the command-line.
-- If no files given, process <code>io.stdin</code>; in list of files,
-- <code>-</code> means <code>io.stdin</code>.
-- <br>FIXME: Make the file list an argument to the function.
-- @param f function to process files with, which is passed
-- <code>(name, arg_no)</code>
function processFiles (f)
  -- N.B. "arg" below refers to the global array of command-line args
  if #arg == 0 then
    table.insert (arg, "-")
  end
  for i, v in ipairs (arg) do
    if v == "-" then
      io.input (io.stdin)
    else
      io.input (v)
    end
    f (v, i)
  end
end
