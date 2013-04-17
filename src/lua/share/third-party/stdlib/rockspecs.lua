-- Rockspec data

-- Variables to be interpolated:
--
-- package
-- version

local version_dashed = version:gsub ("%.", "-")

local default = {
  package = package_name,
  version = version.."-2",
  source = {
    url = "git://github.com/rrthomas/lua-stdlib.git",
  },
  description = {
    summary = "General Lua libraries",
    detailed = [[
    stdlib is a library of modules for common programming tasks,
    including list, table and functional operations, regexps, objects,
    pickling, pretty-printing and getopt.
 ]],
    homepage = "http://github.com/rrthomas/lua-stdlib/",
    license = "MIT/X11",
  },
  dependencies = {
    "lua >= 5.1",
  },
  build = {
    type = "command",
    build_command = "LUA=$(LUA) LUA_INCLUDE=$(LUA_INCDIR) ./configure --prefix=$(PREFIX) --libdir=$(LIBDIR) --datadir=$(LUADIR) && make clean && make",
    install_command = "make install",
    copy_directories = {},
  },
}

if version ~= "git" then
  default.source.branch = "release-v"..version_dashed
else
  default.build.build_command = "autoreconf -i && " .. default.build.build_command
end

return {default=default, [""]={}}
