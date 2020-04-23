import struct, binascii

def check(packet):
	ip_ver = packet[0]>>4;

	if ip_ver == 4:
		fields = struct.unpack('BBHHHBBHLL', packet)

		print("Internet Protocol")
		print("\tVer: {}".format(fields[0]>>4))
		print("\tIHL: {}".format(fields[0]&0x0F))
		print("\tDSCP: {}".format(fields[1]>>2))
		print("\tECN: {}".format(fields[1]&0x03))
		print("\tTotal Length: {}".format(fields[2:3]))

	# print("Internet Protocol")
	# print("\tVER: {}".format(packet[0]>>4))
	# print("\tIHL: {}".format(packet[0]&0x0F))
	# print("\t-- TOS")
	# print("\t\tDSCP: {}".format(packet[1]>>2))
	# print("\t\tECN:  {}".format(packet[1]&0x03))
	# print("\tTotal Length: {}".format(packet[2:3]))

if __name__ == "__main__":
	print("This is not how this works")
