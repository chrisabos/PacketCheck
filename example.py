#!/usr/bin/env python3

import socket
from struct import *

# In order for this to work you have to move
# example.py outside of the package folder
# cp example.py ../
# python3 ../example.py
from PacketCheck import *

# VARIABLES
packet = ''
source_ip = '10.50.25.175'
dest_ip = '172.16.1.15'

# CREATE IP HEADER
ip_ver_ihl = 69
ip_tos = 96
ip_len = 0
ip_id = 1984
ip_frag = 16384
ip_ttl = 128
ip_proto = 16 # CHAOS PROTOCOL
ip_check = 0
ip_saddr = socket.inet_aton(source_ip)
ip_daddr = socket.inet_aton(dest_ip)

ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

# DEFINE DATA
user_data = b'Message goes here'

# CREATE PACKET
packet = ip_header + user_data

# OUT
#s.sendto(packet, (dest_ip, 0))
# instead of sending the packet on a socket, we use the
# packetcheck.check function to display the packet data
packetcheck.check(packet)
