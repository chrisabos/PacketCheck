import binascii

def check(packet):
	hex = binascii.hexlify(packet)

	print("Internet Protocol")
	print("\tVersion: {}".format(hex[0]))

if __name__ == "__main__":
	print("This is not how this works")
