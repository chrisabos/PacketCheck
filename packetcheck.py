import struct, binascii

#import .iana_protocol_numbers, .dscp_translate

from .translators import *

# prints <data> interpreted as an ipv4 packet
def print_ip(data):
	fields = struct.unpack('!BBHHHBBH4s4s', data)

	version = fields[0]>>4
	ihl = fields[0]&0x0F
	dscp = fields[1]>>2
	ecn = fields[1]&0x03
	total_length = fields[2]
	identification = fields[3]
	res = fields[4]>>15
	df = fields[4]>>14&0x01
	mf = fields[4]>>13&0x01
	fragment_offset = fields[4]&0x1FFF
	ttl = fields[5]
	protocol = fields[6]
	header_checksum = fields[7]
	src_ip_addr = int.from_bytes(fields[8], "big")
	dst_ip_addr = int.from_bytes(fields[9], "big")

	print("Internet Protocol v4")
	print("\tVer: {}".format(version))
	print("\tIHL: {}".format(ihl))
	print("\tDSCP: [{}] - {}".format(dscp, dscp_translate.lookup(dscp)))
	print("\tECN: {}".format(ecn))
	print("\tTotal Length: {}{}".format(total_length, (" - HAVE NO FEAR, if the packet has yet to be sent this field will be 0" if total_length == 0 else "")))
	print("\tIdentification: {}".format(identification))
	print("\tFLAGS:")
	print("\t\tRES: {}".format(res))
	print("\t\tDF: {}".format(df))
	print("\t\tMF: {}".format(mf))
	print("\tFragment Offset: {}".format(fragment_offset))
	print("\tTime to Live: {}".format(ttl))
	print("\tProtocol: [{}] - {}".format(protocol, iana_protocol_numbers.lookup(protocol)))
	print("\tHeader Checksum: {}".format(hex(header_checksum)))
	print("\tSource IP Address: {}.{}.{}.{}".format(src_ip_addr>>24&0xFF, src_ip_addr>>16&0xFF, src_ip_addr>>8&0xFF, src_ip_addr&0xFF))
	print("\tDestination IP Address: {}.{}.{}.{}".format(dst_ip_addr>>24&0xFF, dst_ip_addr>>16&0xFF, dst_ip_addr>>8&0xFF, dst_ip_addr&0xFF))
	return ihl * 4

# prints <data> interpreted as ipv4 packet options
def print_ip_options(data):
	print("Options")
	print(data)
	print("Options are a WIP");

# prints <data> interpreted as an ipv6 packet
def print_ipv6(data):
	fields = struct.unpack('!HHHBBqqqq', data)

	version = fields[0]>>12
	traffic_class = fields[0]>>4&0xFF
	flow_label = (int.from_bytes(fields[0]&0x0F, "big")<<16) + fields[1]
	payload_length = fields[2]
	protocol = fields[3]
	hop_limit = fields[4]
	src_ipv6_addr = fields[5]
	src_ipv6_addr2 = fields[6]
	dst_ipv6_addr = fields[7]
	dst_ipv6_addr2 = fields[8]

	print("Internet Protocol v6")
	print("\tVer: {}".format(version))
	print("\tTraffic Class: {}".format(traffic_class))
	print("\tFlow Label: {}".format(flow_label))
	print("\tPayload Length: {}".format(payload_length))
	print("\tProtocol: [{}] - {}".format(protocol, iana_protocol_numbers.lookup(protocol)))
	print("\tHop Limit: {}".format(hop_limit))
	print("\tSource IPv6 Address: {} {}".format(src_ipv6_addr, src_ipv6_addr2))
	print("\tDestination IPv6 Address: {} {}".format(dst_ipv6_addr, dst_ipv6_addr2))

# prints <data> interpreted as a TCP segment
def print_tcp(data):
	print("\nTCP")
	fields = ''
	options = ''
	if len(data) == 20:
		fields = struct.unpack('!HH4s4sBBHHH', data)
	elif len(data) > 20:
		fields = struct.unpack('!HH4s4sBBHHH', data[:20])
		options = data[20:20+(((data[12]>>4) - 5) * 4)]
	else:
		print("-- TCP DATA TOO SHORT --")
		print(data)

	if fields != '':
		src_port = fields[0]
		dst_port = fields[1]
		seq_num = int.from_bytes(fields[2], "big")
		ack_num = int.from_bytes(fields[3], "big")
		offset_res_ns = fields[4]
		tcp_flags = fields[5]
		win_size = fields[6]
		checksum = fields[7]
		urgent_pointer = fields[8]

		print("\tSource port: {}".format(src_port))
		print("\tDestination port: {}".format(dst_port))
		print("\tSeq Number: {}".format(seq_num))
		print("\tAck Number: {}".format(ack_num))
		print("\tOffset: {}".format(offset_res_ns>>4))
		print("\tReserved: {}".format(offset_res_ns>>1&0x07))
		print("\tNS: {}".format(offset_res_ns&0x01))
		print("\tTCP Flags:")
		print("\t\tCWR: {}".format(tcp_flags>>7&0x01))
		print("\t\tECE: {}".format(tcp_flags>>6&0x01))
		print("\t\tURG: {}".format(tcp_flags>>5&0x01))
		print("\t\tACK: {}".format(tcp_flags>>4&0x01))
		print("\t\tPSH: {}".format(tcp_flags>>3&0x01))
		print("\t\tRST: {}".format(tcp_flags>>2&0x01))
		print("\t\tSYN: {}".format(tcp_flags>>1&0x01))
		print("\t\tFIN: {}".format(tcp_flags&0x01))
		print("\tWindow Size: {}".format(win_size))
		print("\tChecksum: {}".format(hex(checksum)))
		print("\tUrgent Pointer: {}".format(urgent_pointer))

	# TODO: complete option list
	if options != '':
		print("\tTCP Options")
		for i, b in enumerate(options):
			if b == 0:
				print("\t\t0: End of Option List")
			elif b == 1:
				print("\t\t1: No-Operation")
			else:
				print(b)

# prints <data> interpreted as a UDP datagram
def print_udp(data):
	print("\nUDP")
	fields = ''
	if len(data) == 8:
		fields = struct.unpack('!HHHH', data)
	elif len(data) > 8:
		print("-- UDP DATA TOO LONG --")
		print(data)
	else:
		print("-- UDP DATA TOO SHORT --")
		print(data)

	if fields != '':
		src_port = fields[0]
		dst_port = fields[1]
		length = fields[2]
		checksum = hex(fields[3])

		print("\tSource port: {}".format(src_port))
		print("\tDestination port: {}".format(dst_port))
		print("\tLength: {}".format(length))
		print("\tChecksum: {}".format(checksum))

# checks a packet
def check(packet):
	print("### PacketCheck ###\n")

	ip_ver = packet[0]>>4;
	proto = -1
	current_byte = 0

	# is this an ipv4 packet?
	if ip_ver == 4:
		ihl = packet[0]&0x0F
		proto = packet[9]
		print_ip(packet[current_byte:(current_byte+20)])
		current_byte += 20

		# does this packet have options?
		if ihl > 5:
			options_len = (ihl - 5) * 4
			print_ip_options(packet[current_byte:current_byte+options_len])
			current_byte += options_len

	# is this an ipv6 packet?
	elif ip_ver == 6:
		proto = packet[6]
		print_ipv6(packet[current_byte:current_byte+40])
		current_byte += 40

	if proto == 0x06: # proto == TCP
		if len(packet) > current_byte + 20:
			print_tcp(packet[current_byte:])
		else:
			print("Network layer specified TCP protocol but packet is too short")
	elif proto == 0x11: # proto == UDP
		print_udp(packet[current_byte:current_byte+8])


# idk why someone would ever run this script but here it is
if __name__ == "__main__":
	print("This is not how this works")
