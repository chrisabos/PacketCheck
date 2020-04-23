import binascii

def check(packet):
	print("Internet Protocol")
	print("\tVER: {}".format(packet[0]))
	print("\tIHL: {}".format(packet[0]))
	print("\t-- TOS")
	print("\t\tDSCP: {}".format(packet[1]>>2))
	print("\t\tECN:  {}".format(packet[1]&0x03))
	print("\tTotal Length: {}".format(packet[2:3]))

if __name__ == "__main__":
	print("This is not how this works")
