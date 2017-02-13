try:
	import socket
	import argparse
	from STcommon import configDebugLog
	from ipaddress import ip_address
	from os.path import isfile
	from Crypto.Cipher import PKCS1_OAEP
	from Crypto.PublicKey import RSA
	from Crypto.Cipher import AES
	from Crypto import Random
	from binascii import hexlify
except ImportError as e:
	print("[-] {}, exiting".format(e))
	exit(1)

def contactServer(HOST, PORT, CIPHER, tryAgain = 6):

	AES_key = Random.new().read(32)
	msg = CIPHER.encrypt("3317BLT5_#_{0}_#_{1}\n".format(socket.gethostname()[:32], hexlify(AES_key).decode()).encode())

	# As you can see, there is no connect() call; UDP has no connections.
	# Instead, data is directly sent to the recipient via sendto().
	logger.info("[ ] sending message to {}:{}".format(HOST,PORT))
		
	#try connecting tryAgain number of times
	for i in range(tryAgain):
		logger.debug("[ ] Attempting to contact server")
		received = sendAndRecv(msg, HOST, PORT)
		if received:
			#break so that we don't exit... control flow is great
			logger.debug("[+] Got a reply")
			break
	else:
		logger.critical("[-] Unable to connect to server, quiting.")
		exit(2)

	#set up the AES cipher based on what we got
	try:
		iv = received[:AES.block_size]
		cipherAES = AES.new(AES_key, AES.MODE_CFB, iv)
	except ValueError:
		logger.warning("[-] Server reply contains invalid IV")
		return False

	reply = cipherAES.decrypt(received[AES.block_size:])

	if reply.decode().split("_#_")[1] == socket.gethostname().strip()[:32]:
		logger.info("[+] Location logged to server")
		return True
	else:
		logger.warning("[-] Invalid server response")
		return False

def sendAndRecv(msg, host, port, timeout=10):
	# SOCK_DGRAM is the socket type to use for UDP sockets 
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.settimeout(timeout)
	try:
		sock.sendto(msg, (host, port))
		logger.info("[ ] message sent, waiting for reply.")
		received = sock.recv(1024).strip()
		return received
	except (socket.gaierror, socket.timeout) as e:
		logger.warning("[-] Could not reach server, {}.".format(e))
		return None

def parseArgs():
	'''Parses args using the argparse lib'''
	parser = argparse.ArgumentParser(description='Location logging server')

	parser.add_argument('-a', '--address', metavar='ADDRESS', type=ip_address)
	parser.add_argument('-p', '--port', metavar='PORT', type=int)

	return parser.parse_args()

def main():
	HOST, PORT = "localhost", 3145
	logger.info("[ ] Starting location logging")

	args = parseArgs()

	#check our args and update vars accordingly
	if args.address:
		HOST = str(args.address)
	if args.port:
		PORT = args.port

	#check if we have the public key 
	if not isfile("./python.pub"):
		logger.critical("[-] Missing public key, Exiting")
		exit(3)

	#get the public key and create the cipher
	with open("./python.pub", "r") as keyFile:
		cipherRSA = PKCS1_OAEP.new(RSA.importKey(keyFile.read()))

	while(not contactServer(HOST, PORT, cipherRSA)):
		logger.info("[ ] Trying again.")

if __name__ == "__main__":
	logger = configDebugLog("/var/log/skip_trace.log")
	main()
	exit(0)