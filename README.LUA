EXPERIMENTAL!

Requires:
  LuaJIT >= 2.0.0 (will use bundled LuaJIT if it isn't already installed)

Building.
   mkdir build
   cd build/
   cmake -DENABLE_LUA=On ..
   make
   sudo make install

Example Scripts:
   See example scripts under src/lua/share/scripts/ or when installed under
   /usr/local/share/ettercap/lua/scripts/.

Script Execution:
   Pass the script to the --lua-script parameter. More scripts can be
   specficied separated with comma (no spaces).

   ettercap [OPTIONS] --lua-script=<script1>[,<script2>,...]

Script Parameters:
   You can pass parameters to the LUA script by passing them to the
   --lua-args parameter in key-value pairs. Multiple key-value pairs can be
   specified separated with comma (no spaces).

   ettercap [OPTIONS] --lua-args n1=v1,[n2=v2,...]

   To access these parameters in the LUA script, they're available as a
   table variable called SCRIPT_ARGS. So the following example access the
   parameter key "n1":

   ettercap.log("value for n1: %s", SCRIPT_ARGS["n1"])
