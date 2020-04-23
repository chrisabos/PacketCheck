import struct, binascii

import iana_protocol_numbers

def check(packet):
	print("### PacketCheck ###\n")

	ip_ver = packet[0]>>4;

	if ip_ver == 4:
		fields = struct.unpack('!BBHHHBBHll', packet[:20])

		print("Internet Protocol v4")
		print("\tVer: {}".format(fields[0]>>4))
		print("\tIHL: {}".format(fields[0]&0x0F))
		print("\tDSCP: {}".format(fields[1]>>2))
		print("\tECN: {}".format(fields[1]&0x03))
		print("\tTotal Length: {}".format(fields[2]))
		print("\tIdentification: {}".format(fields[3]))
		print("\tFLAGS:")
		print("\t\tRES: {}".format(fields[4]>>15))
		print("\t\tDF: {}".format(fields[4]>>14&0x01))
		print("\t\tMF: {}".format(fields[4]>>13&0x01))
		print("\tFragment Offset: {}".format(fields[4]&0x1FFF))
		print("\tTime to Live: {}".format(fields[5]))
		print("\tProtocol: [{}] - {}".format(fields[6], iana_protocol_numbers.lookup(fields[6])))
		print("\tHeader Checksum: {}".format(hex(fields[7])))
		print("\tSource IP Address: {}.{}.{}.{}".format(fields[8]>>24&0xFF, fields[8]>>16&0xFF, fields[8]>>8&0xFF, fields[8]&0xFF))
		print("\tDestination IP Address: {}.{}.{}.{}".format(fields[9]>>24&0xFF, fields[9]>>16&0xFF, fields[9]>>8&0xFF, fields[9]&0xFF))

	elif ip_ver == 6:
		fields = struct.unpack('!HHHBBqqqq', packet[:40])

		print("Internet Protocol v6")
		print("\tVer: {}".format(fields[0]>>12))
		print("\tTraffic Class: {}".format(fields[0]>>4&0xFF))
		print("\tFlow Label: {}+{}".format(fields[0]&0x0F, fields[1]))
		print("\tPayload Length: {}".format(fields[2]))
		print("\tProtocol: [{}] - {}".format(fields[3], iana_protocol_numbers.lookup(fields[3])))
		print("\tHop Limit: {}".format(fields[4]))
		print("\tSource IPv6 Address: {} {}".format(fields[5], fields[6]))
		print("\tDestination IPv6 Address: {} {}".format(fields[7], fields[8]))


	# print("Internet Protocol")
	# print("\tVER: {}".format(packet[0]>>4))
	# print("\tIHL: {}".format(packet[0]&0x0F))
	# print("\t-- TOS")
	# print("\t\tDSCP: {}".format(packet[1]>>2))
	# print("\t\tECN:  {}".format(packet[1]&0x03))
	# print("\tTotal Length: {}".format(packet[2:3]))

if __name__ == "__main__":
	print("This is not how this works")
