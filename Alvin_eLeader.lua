local proto_cat = Proto('Alvin','Alvin - eLeader Protocol')

function cat_proc(_buf, pkt, tree)
    local dataPacketLength = tonumber(_buf(0, 4):le_uint())
    local desiredPacketLength = _buf:len() 
    pkt.cols.protocol = 'eLeader'
    pkt.cols.info = string.format('%d*',dataPacketLength)
    local subtree = tree:add(proto_cat,_buf(),'eLeader Protocol')
    local packet = subtree:add(_buf(0, desiredPacketLength), string.format("Content %d",_buf:len()))
    packet:add(_buf(0, 4), "Packet length: " .. _buf(0, 4):le_uint())
    packet:add(_buf(4, 44), string.format("Header(Trcode:%d)",_buf(12,2):le_uint()))	
    packet:add(_buf(48 , dataPacketLength), "Data:" .. dataPacketLength)
end

local function get_msg_length(tvbuf, pktinfo, offset)
    local lengthVal = tvbuf:range(offset, 4):le_uint() + 48
    return lengthVal
end

function proto_cat.dissector(buf, pkt, tree)
    dissect_tcp_pdus(buf,tree,4,get_msg_length,cat_proc)
    bytes_consumed = buf:len()
    return bytes_consumed
end

DissectorTable.get("tcp.port"):set(443, proto_cat)
