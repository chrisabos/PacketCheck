import binascii

def check(packet):
	hex = binascii.hexlify(packet)
	print(hex)

	print("Internet Protocol")
	print("\tVER: {}".format(hex[0]))
	print("\tIHL: {}".format(hex[1]))
	print("\t-- TOS")
	print("\t\tDSCP: {}".format(hex[2:2]>>2))
	print("\t\tECN:  {}".format(hex[2:2]&0x03))
	print("\tTotal Length: {}".format(hex[4:4]))

if __name__ == "__main__":
	print("This is not how this works")
