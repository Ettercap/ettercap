local reg = {}

function reg.workspace_exists(ns)
	return reg[ns] ~= nil
end
function reg.create_namespace(ns)
	if not  reg.workspace_exists(ns) then
		reg[ns] = {}
	end
end

function reg.get_namespace(ns)
	if reg.workspace_exists(ns) then	
		return reg[ns]
	else
		return nil
	end
end

function reg.delete_namespace(ns)
	if reg.workspace_exists(ns) then
		reg[ns] = nil
	end
end

return reg
