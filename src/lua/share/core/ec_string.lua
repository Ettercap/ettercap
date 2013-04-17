starts_with = function (str,val)
   if str == nil or val == nil then
      return 0
   end

   local spos, endpos = string.find(str,val)
   if spos == nil   then
      return 0
   end
   return 1
end
