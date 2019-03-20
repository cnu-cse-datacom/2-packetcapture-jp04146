import socket
import struct
import time


def parsing_ethernet_header(data) :
        ethernet_header = struct.unpack("!6c6c2s",data)
        ether_dst_add = convert_ether_addr(ethernet_header[0:6])
        ether_scr_add = convert_ether_addr(ethernet_header[6:12])
        ip_header = "0x" + hex(ethernet_header[12])

        print("=======ethernet header=======")
        print("dst_mac_address:", ether_dst_add)
        print("src_mac_address:", ether_src_add)
        print("ip_version:", ip_header)

def convert_ether_addr(data) : 
        ethernet_addr = list()
        for i in data:
                ethernet_addr.append(i.hex())
        ethernet_addr = ":".join(ethernet_addr)
        return ethernet_addr

def parsing_ip_header(data) : 
        ip_header = struct.unpack("!1c1c2s2s2s1c1c2s4c4c",data)
        print("=======IP header=======")
        print("ip_version:", hex(ip_header[0][0]) 
        #print("ip_header_length:", hex(ip_header[0][1]) 
        #print("type_of_service:", hex(ip_header[1])) 
        print("total_length:", hex(ip_header[2]))
        print("identification:",hex(ip_header[3]))

        print("flag:", hex(ip_header[4]))
        print(">>reserved_bit:", hex(ip_header[4][0]))
        print(">>not_fragment:", hex(ip_header[4][1]))
        print(">>more_fragment:", hex(ip_header[4][2]))
        print(">>fragments_offset:", hex(ip_header[4][3]))

        print("time_to_live:", hex(ip_header[5]))
        print("protocol:", hex(ip_header[6]))
        print("cheksum:", hex(ip_header[7]))
        print("src_ip_addr:", convert_ip_addr(ip_header[8:12])
        print("dst_ip_addr:", convert_ip_addr(ip_header[12:16])

def convert_ip_addr(data) :
        ip_addr = list()
        for i in data:
                ip_addr.append(i.hex())
        ip_addr = ".".join(ip_addr)
        return ip_addr

def parsing_tcp_header(data) :
        tcp_header = struct.unpack("!2s2s4s4s2s2s2s2s", data)

        print("=======TCP header=======")
        print("src__port:", hex(tcp_header[0]))
        print("dst_port:", hex(tcp_header[1]))
        print("sequence_num:", hex(tcp_header[2]))
        print("acknowledge_num:", hex(tcp_header[3]))
        print("header_length:", hex(tcp_header[4][0]))
        print("flags:", hex(tcp_header[4][1:4]))

        print("window_size:", hex(tcp_header[5]))
        print("checksum:", hex(tcp_header[6]))
        print("urgent_pointer:", hex(tcp_header[7].hex))

def parsing_udp_header(data):
        udp_header = struct.unpack("!2s2s2s2s", data)

        print("=======UDP header=======")
        print("src_port:", hex(udp_header[0]))
        print("dsr_port", hex(udp_header[1]))
        print("length:", hex(udp_header[2]))
        print("checksum:", hex(udp_header[3]))

mk_sckt = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))
i=0
while True:
        print("packet{0}".format(i))
        data = mk_sckt.recvfrom(99999)

        parsing_ethernet_header(data[0][0:14])

        tcp_udp_select=parsing_ip_header(data[0][14:34])
        if(tcp_udp_select == 6) :
                parsing_tcp_header(data[0][34:54])
        elif(tcp_udp_select == 17) :
                parsing_udp_header(data[0][34:42])

        time.sleep(1)
        i += 1


