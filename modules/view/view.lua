local kres = require('kres')
local policy = require('policy')
local ffi = require('ffi')
local C = ffi.C

-- Module declaration
local view = {
	key = {},
	src = {},
	dst = {},
}

-- @function View based on TSIG key name.
function view.tsig(view, tsig, policy)
	view.key[tsig] = policy
end

-- @function View based on source IP subnet.
function view.addr(view, subnet, policy, dst)
	local subnet_cd = ffi.new('char[16]')
	local family = C.kr_straddr_family(subnet)
	local bitlen = C.kr_straddr_subnet(subnet_cd, subnet)
	local t = {family, subnet_cd, bitlen, policy}
	table.insert(dst and view.dst or view.src, t)
	return t
end

-- @function Match IP against given subnet
local function match_subnet(family, subnet, bitlen, addr)
	return (family == addr:family()) and (C.kr_bitcmp(subnet, addr:ip(), bitlen) == 0)
end

-- @function Find view for given request
local function evaluate(view, req)
	local client_key = req.qsource.key
	local match_cb = (client_key ~= nil) and view.key[client_key:owner()] or nil
	-- Search subnets otherwise
	if match_cb == nil then
		if req.qsource.addr ~= nil then
			for i = 1, #view.src do
				local pair = view.src[i]
				if match_subnet(pair[1], pair[2], pair[3], req.qsource.addr) then
					match_cb = pair[4]
					break
				end
			end
		elseif req.qsource.dst_addr ~= nil then
			for i = 1, #view.dst do
				local pair = view.dst[i]
				if match_subnet(pair[1], pair[2], pair[3], req.qsource.dst_addr) then
					match_cb = pair[4]
					break
				end
			end
		end
	end
	return match_cb
end

-- @function Return policy based on source address
function view.rule_src(action, subnet)
	local subnet_cd = ffi.new('char[16]')
	local family = C.kr_straddr_family(subnet)
	local bitlen = C.kr_straddr_subnet(subnet_cd, subnet)
	return function(req, _)
		local addr = req.qsource.addr
		if addr ~= nil and match_subnet(family, subnet_cd, bitlen, addr) then
			return action
		end
	end
end

-- @function Return policy based on destination address
function view.rule_dst(action, subnet)
	local subnet_cd = ffi.new('char[16]')
	local family = C.kr_straddr_family(subnet)
	local bitlen = C.kr_straddr_subnet(subnet_cd, subnet)
	return function(req, _)
		local addr = req.qsource.dst_addr
		if addr ~= nil and match_subnet(family, subnet_cd, bitlen, addr) then
			return action
		end
	end
end

-- @function Module layers
view.layer = {
	begin = function(state, req)
		if state == kres.FAIL then return state end
		req = kres.request_t(req)
		local match_cb = evaluate(view, req)
		if match_cb ~= nil then
			local action = match_cb(req, req:current())
			return policy.enforce(state, req, action) or state
		end
		return state
	end
}

return view
