try:
	import logging
	import socket
	from os.path import isfile
	from Crypto.Cipher import PKCS1_OAEP
	from Crypto.PublicKey import RSA
	from Crypto.Cipher import AES
except ImportError as e:
	print("[-] {}, exiting".format(e))
	exit(1)

def main(HOST, PORT, CIPHER, tryAgain = 6):

	msg = CIPHER.encrypt("3317BLT5 {0}\n".format(socket.gethostname()).encode())

	# As you can see, there is no connect() call; UDP has no connections.
	# Instead, data is directly sent to the recipient via sendto().
	print("[ ] sending message to {}:{}".format(HOST,PORT))
		
	#try connecting tryAgain number of times
	for i in range(tryAgain):
		print("[ ] Attempting to contact server")
		received = sendAndRecv(msg, HOST, PORT)
		if received:
			#break so that we don't exit... control flow is great
			print("[+] Got a reply")
			break
	else:
		print("[-] Unable to connect to server, quiting.")
		exit(2)

	#set up the AES cipher based on what we got
	try:
		iv = received[:AES.block_size]
		cipherAES = AES.new(socket.gethostname()[:32].center(32), AES.MODE_CFB, iv)
	except ValueError:
		print("[-] Server reply contains invalid IV")
		return False
	reply = cipherAES.decrypt(received[AES.block_size:])


	if reply.decode().split("\t")[1] == socket.gethostname()[:5]:
		print("[+] Location logged to server")
		return True
	else:
		print("[-] Invalid server response")
		return False

def sendAndRecv(msg, host, port, timeout=10):
	# SOCK_DGRAM is the socket type to use for UDP sockets 
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.settimeout(timeout)
	try:
		sock.sendto(msg, (host, port))
		print("[ ] message sent, waiting for reply.")
		received = sock.recv(1024).strip()
		return received
	except (socket.gaierror, socket.timeout) as e:
		print("[-] Could not reach server, {}.".format(e))
		return None
		
def configDebugLog():
	logFileName = "/var/log/skip_trace.log"

	log_file = logging.FileHandler(logFileName)
	log_file.setLevel(logging.DEBUG)
	log_file.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

	# ERROR level or higher should be output to console as well
	log_console = logging.StreamHandler()
	log_console.setLevel(logging.ERROR)
	log_console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

	logger.getLogger('main_logger')
	logger.addHandler(log_console)
	logger.addHandler(log_file)

if __name__ == "__main__":
	configDebugLog()
	SERVER, PORT = "localhost", 3145
	print("[ ] Starting location logging")

	#check if we have the public key 
	if not isfile("./python.pub"):
		print("[-] Missing public key, Exiting")
		exit(3)

	#get the public key and create the cipher
	with open("./python.pub", "r") as keyFile:
		cipherRSA = PKCS1_OAEP.new(RSA.importKey(keyFile.read()))

	while(not main(SERVER, PORT, cipherRSA)):
		print("[ ] Trying again.")
	exit(0)
