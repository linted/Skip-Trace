try:
	import socketserver
	import argparse
	from time import strftime
	from STcommon import configDebugLog
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
				logFile.write(strftime('%b  %d %H:%M:%S  {0} checking in at {1}\n'.format(clientName,self.client_address[0])))
				print("[+] IP Logged to file")
			
		except BaseException as e:
			logger.warning("[-] Failure: {}".format(e))
			reply = Random.new().read(AES.block_size+13)
			logger.info("[-] Sending random message")

		else:
			#create AES cipher
			iv = Random.new().read(AES.block_size)
			AEScipher = AES.new(key, AES.MODE_CFB, iv)
			reply = iv + AEScipher.encrypt(strftime('_#_{0}_#_%H:%M:%S:%f\n'.format(clientName)))
			logger.info("[+] Sending success message")

		finally:
			socket.sendto(reply + b"\n", self.client_address)
			logger.info("[+] Done")

def is_valid_hostname(hostname):
    hostname = hostname.rstrip('.')
    labels = hostname.split('.')
    # the TLD must be not all-numeric
    if len(labels) > 1 and labels[-1].isdigit():
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

def parseArgs():
	'''Parses args using the argparse lib'''
	parser = argparse.ArgumentParser(description='Location logging server')

	parser.add_argument('-a', '--address', metavar='ADDRESS', type=ip_address)
	parser.add_argument('-p', '--port', metavar='PORT', type=int)

	return parser.parse_args()

def main():
	HOST, PORT = "0.0.0.0", 3145

	args = parseArgs()

	#check our args and update vars accordingly
	if args.address:
		HOST = str(args.address)
	if args.port:
		PORT = args.port

	#check if we have the private key
	if not isfile("./python.pem"):
		logger.critical("[-] Missing private key, Exiting")
		exit(-2)

	with open("./python.pem", "r") as keyFile:
		MyUDPHandler.RSAcipher = PKCS1_OAEP.new(RSA.importKey(keyFile.read()))

	server = socketserver.UDPServer((HOST, PORT), MyUDPHandler)
	server.serve_forever()

if __name__ == "__main__":
	logger = configDebugLog("/var/log/skip_trace.log")
	main()
