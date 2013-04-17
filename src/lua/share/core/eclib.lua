---
-- Some helper functions
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


--- Basic Split taken from http://lua-users.org/wiki/SplitJoin
-- @param str 
-- @param pat 
-- @return table
split = function(str, pat)
   local t = {}  -- NOTE: use {n = 0} in Lua-5.0
   local fpat = "(.-)" .. pat
   local last_end = 1
   local s, e, cap = str:find(fpat, 1)
   while s do
      if s ~= 1 or cap ~= "" then
   table.insert(t,cap)
      end
      last_end = e+1
      s, e, cap = str:find(fpat, last_end)
   end
   if last_end <= #str then
      cap = str:sub(last_end)
      table.insert(t, cap)
   end
   return t
end

---Returns a string representation of a hex dump of a string (containing binary bytes even zero)
hexdump = function(s)
	local manLine="" --human readable format of the current line
	local hexLine="" --hexadecimal representation of the current line
	local address=0     --the address where the current line starts
	local LINE_LENGTH=16 --how many characters per line?
	local ADDRESS_LENGTH=4 --how many characters for the address part?
	local ret=""
	if not hex then
		hex={}
		local digit={[0]="0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"}
		for i=0,15 do for j=0,15 do hex[i*16+j]=digit[i]..digit[j] end end
	end
	for i=1,s:len() do
		local ch=s:sub(i,i)
		if ch:find("%c") then ch="." end--if ch is a control character, assign some default value to it
		manLine=manLine..ch
		hexLine=hexLine..hex[s:byte(i)].." "
		if (i % LINE_LENGTH)==0 or i==s:len() then
			--print(string.format("%04u | %-48s | %s",address,hexLine,manLine))
			ret=ret..string.format("%0"..ADDRESS_LENGTH.."u | %-"..3*LINE_LENGTH.."s| %s\n",address,hexLine,manLine)
			manLine,hexLine="",""
			address=i
		end
	end
	return ret
end

local eclib = {}

eclib.split = split
eclib.hexdump = hexdump

return eclib
