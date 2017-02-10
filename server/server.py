try:
	from STcommon import *
	import socketserver
	import time
	import sqlite3
	import argparse
	from ipaddress import ip_address
	from os.path import isfile
	from Crypto.Cipher import PKCS1_OAEP
	from Crypto.PublicKey import RSA
	from Crypto.Cipher import AES
	from Crypto import Random
	from binascii import unhexlify
except ImportError as e:
	print("[-] {}, exiting".format(e))
	exit(1)

months = ["Jan", "Feb", "Mar", "Apr", "May", "June", "July", "Aug", "Sept", "Oct", "Nov", "Dec"]

class MyUDPHandler(socketserver.BaseRequestHandler):
	RSAcipher = None

	def handle(self):
		data, socket = self.request

		logger.info("[ ] Recieved request")
		try:
			msg = self.RSAcipher.decrypt(data).decode().split("_#_", 2)

			#check for valid magic number
			if (msg[0] != '3317BLT5'):
				raise BaseException("Invalid magic number")

			#get client Name
			clientName = msg[1].strip()[:32]
			if 0 < len(clientName) <= 253:
				if !(is_valid_hostname(clientName)):
					raise ValueError("Invalid hostname")
			else
				raise ValueError("Invalid hostname size")

			#create AES key for reply
			key = unhexlify(msg[2].strip())
			if len(key) != 32:
				raise ValueError("Invalid key size")

			with open("/var/log/locationLog", "a") as logFile:
				date = time.localtime()
				logFile.write("{0}  {1:02} {2:02}:{3:02}:{4:02}  {6} Checking in at {5}\n".format(months[date.tm_mon - 1], date.tm_mday, date.tm_hour, date.tm_min, date.tm_sec, self.client_address[0], clientName))
				logger.info("[+] IP Logged to file")
			
		except BaseException as e:
			logger.warning("[-] Failure: {}".format(e))
			reply = Random.new().read(AES.block_size+13)
			logger.info("[-] Sending random message")

		else:
			#create AES cipher
			iv = Random.new().read(AES.block_size)
			AEScipher = AES.new(key, AES.MODE_CFB, iv)
			reply = iv + AEScipher.encrypt("\t{0}\t{1:02}:{2:02}\n".format(clientName,date.tm_hour,date.tm_min))
			logger.info("[+] Sending success message")

		finally:
			socket.sendto(reply + b"\n", self.client_address)
			logger.info("[+] Done")

def is_valid_hostname(hostname):
    hostname = hostname.rstrip('.')
    labels = hostname.split('.')
    # the TLD must be not all-numeric
    if labels[-1].isdigit():
        return False
    for label in labels:
    	#Check for length
        if len(label) > 63:
            return False
        #Check for invalid characters
        if len(label.translate(is_valid_hostname.translation_table)) > 0 :    
            return False
        #Check that no label start or ends with a hyphen
        if label[0] == '-' or label[-1] == '-':
            return False
    return True
is_valid_hostname.translation_table = dict.fromkeys(map(ord,string.ascii_letters + string.digits + '-'),None)

def keyGen(path):
	key = RSA.generate(2048)
	with open(path +'/python.pem','wb') as privateKey:
		privateKey.write(key.exportKey('PEM'))
	with open(path+ '/python.pub', 'wb') as publicKey:
		publicKey.write(key.publickey().exportKey('PEM'))

def parseArgs():
	'''Parses args using the argparse lib'''
	parser = argparse.ArgumentParser(description='Location logging server')

	parser.add_argument('-g', '--generate-keys', metavar='PATH', type=str)
	parser.add_argument('-a', '--address', metavar='ADDRESS', type=ip_address)
	parser.add_argument('-p', '--port', metavar='PORT', type=int)

	return parser.parse_args()

if __name__ == "__main__":
	logger = configDebugLog("/var/log/skip_trace.log")
	HOST, PORT = "0.0.0.0", 3145

	args = parseArgs()

	#check our args and update vars accordingly
	if args.generate_keys:
		keyGen(args.generate_keys)
	if args.address:
		HOST = str(args.address)
	if args.port:
		PORT = args.port

	#check if we have the private key
	if not isfile("./python.pem"):
		logger.critical("[-] Missing public key, Exiting")
		exit(-2)

	with open("./python.pem", "r") as keyFile:
		MyUDPHandler.RSAcipher = PKCS1_OAEP.new(RSA.importKey(keyFile.read()))

	server = socketserver.UDPServer((HOST, PORT), MyUDPHandler)
	server.serve_forever()
