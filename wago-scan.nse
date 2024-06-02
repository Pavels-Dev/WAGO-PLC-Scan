local nmap = require('nmap')
local stdnse = require('stdnse')
local os = require('os')
local packet = require("packet")

description = [[

]]

---
-- @usage
-- sudo nmap <target> --script 'Wago-Scan.nse' -p 6626 --script-args 'interface=<interface>'

--
-- @output
--PORT     STATE SERVICE
--6626/tcp open  wago-service
--| Wago Scan: 
--|   
--|     Device: X
--|   
--|     Hardware_Version: X
--|   
--|     Serial_Number: X
--|   
--|     Software_Version: X
--|   
--|     Firmware_Loader_Version: X
--|   
--|     Baud: X
--|   
--|     Firmware_Burn_Date: X
--|   
--|_    QS_String: X


author = "Pavelsdev"

function wait(seconds)
    local start = os.clock()
    while os.clock() - start < seconds do end
end

local function send_icmp_echo(target, data)
    stdnse.debug1("Sending ICMP: %s", data)
    local handle = io.popen("nping --icmp -c 1 --icmp-type echo --data '".. data .. "' "..  target.ip)
    local icmp_output = handle:read("*a")
    handle:close()
    stdnse.debug1("ICMP Returned: %s", icmp_output)
    if icmp_output then
       return true
    else
       return false
    end
end

function split_string (inputstr, sep)
    if sep == nil then
            sep = "%s"
    end
    local t={}
    for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
            table.insert(t, str)
    end
    return t
end

function format_helper(input, name)
    for _, str in ipairs(input) do
        if string.find(str, name) then
            if name == "FWL" then
              return split_string(str,"=")[2] .. " " .. split_string(str,"=")[3]
            end
            return split_string(str,"=")[2]
        end
        
    end
end

function format_output(message)
    local output = stdnse.output_table()
    local content = split_string(message,";")
    output= {
        {Device = format_helper(content, "DESCR")},
        {Hardware_Version =format_helper(content, "HW")},
        {Serial_Number = format_helper(content, "SN")},
        {Software_Version = format_helper(content, "SW")},
        {Firmware_Loader_Version = format_helper(content, "FWL")},
        {Baud = format_helper(content, "BAUD")},
        {Firmware_Burn_Date = format_helper(content, "BURN")},
        {QS_String = format_helper(content, "QS")},
    }
    return output
end

function openFirewall()
    os.execute("iptables -A INPUT -p tcp --dport " .. src_port .." -j DROP")
end

function closeFirewall()
    os.execute("iptables -D INPUT -p tcp --dport " .. src_port .." -j DROP")
end

function pack_ip(ip)
    local packed_ip = string.pack("BBBB", ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)"))
    return packed_ip
end

function to_hex(str)
    local result = "\\x" -- Start with the insertChar at the beginning
    for i = 1, #str - 1 do -- Adjusted to skip the last character
        result = result .. string.sub(str, i, i)
        if i % 2 == 0 then
            result = result .. "\\x"
        end
    end
    -- Add the last character without the insertChar
    result = result .. string.sub(str, #str)
    return result
end

portrule = function(host, port)
 return port.protocol == "tcp" and port.state == "open" and port.number == 6626
end

function send_tcp_raw(dnet, data, host)
    local pkt = stdnse.fromhex(data)
  
    local tcp = packet.Packet:new(pkt, pkt:len())
  
    tcp:ip_set_bin_src(host.bin_ip_src)
    tcp:ip_set_bin_dst(host.bin_ip)
    tcp:tcp_set_dport(6626)
    
    tcp:tcp_set_sport(src_port)
    tcp:tcp_set_seq(seq)
    tcp:set_u32(tcp.tcp_offset+8,ack)
    tcp:tcp_count_checksum(tcp.ip_len)
    tcp:ip_count_checksum()
    
    local status, err = dnet:ip_send(tcp.buf, host.ip)
end

action = function(host, port)
    if os.getenv("SUDO_USER") == nil then
        return "This script requires sudo Priviliges to run"
    end
    interface = stdnse.get_script_args("interface")
    src_ip = nmap.get_interface_info(interface).address
    dst_ip = host.ip  
    src_port = math.random(49152, 65535)


    openFirewall()

    local socket = nmap.new_socket()
    socket:pcap_open(interface, 64, true, "src host "..host.ip.." and src port 6626 and tcp")

    local dnet = nmap.new_dnet()

    local status, err = dnet:ip_open()

    if not status then
        stdnse.debug1("Failed to open IP interface: %s", err)
        return
    end

    if send_icmp_echo(host,"6162636465666768696a6b6c6d6e6f7071727374757677616263646566676869") then
        stdnse.debug1("First ICMP Send and received")

        -- Syn Paket
        ack = 0
        seq = 1200033097
        send_tcp_raw(dnet, "4500003430d5400080060000c0a80007c0a80002cfd919e247870d49000000008002faf081800000020405b40103030801010402", host)

        local status, plen, l2_data, l3_data, time = socket.pcap_receive(socket)
        local tcp_seq = string.byte(l3_data, 25) * 2^24 + string.byte(l3_data, 26) * 2^16 + string.byte(l3_data, 27) * 2^8 + string.byte(l3_data, 28)

        stdnse.debug1("TCP Handshake initialized")
        wait(0.002)

        --Ack Packet
        seq = seq + 1
        ack = tcp_seq +1
        send_tcp_raw(dnet, "4500002830d6400080060000c0a80007c0a80002cfd919e247870d4af05a46545010020181740000", host)

        if send_icmp_echo(host, "4545454545454545454545454545454545454545454545454545454545454545") then
            stdnse.debug1("Second answer received")
            -- First Data Packet
            ack = tcp_seq
            send_tcp_raw(dnet, "4500004430d8400080060000c0a80007c0a80002cfd919e247870d4af05a46545018020181900000881201000100010000000000000000000a0001040000090000000100", host)
            stdnse.debug1("First tcp sent")

            wait(0.1)

            -- Second Data Packet
            ack = tcp_seq + 33
            seq = seq + 28
            send_tcp_raw(dnet, "4500003c30d9400080060000c0a80007c0a80002cfd919e247870d66f05a467450180201818800008812020001000100000000000000000002000801", host)
            stdnse.debug1("Second tcp sent")

            local handle = io.popen("sudo tcpdump 'src host ".. host.ip .." and src\
             port 6626 and len > 250 and tcp' -i " .. interface .." -v -A -c 1")
            local data = handle:read("*a")
            handle:close()


            local status, err = dnet:ip_close()
            closeFirewall()
            return format_output(data)

        end

    end

end