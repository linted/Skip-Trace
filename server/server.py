try:
	import socketserver
	import time
	import sqlite3
	import argparse
	from ipaddress import ip_address
	from sys import argv
	from os.path import isfile
	from Crypto.Cipher import PKCS1_OAEP
	from Crypto.PublicKey import RSA
	from Crypto.Cipher import AES
	from Crypto import Random
except ImportError as e:
	print("[-] {}, exiting".format(e))
	exit(1)

months = ["Jan", "Feb", "Mar", "Apr", "May", "June", "July", "Aug", "Sept", "Oct", "Nov", "Dec"]

class MyUDPHandler(socketserver.BaseRequestHandler):
	RSAcipher = None

	def handle(self):
		data = self.request[0]
		socket = self.request[1]

		print("[ ] Recieved request")
		try:
			msg = self.RSAcipher.decrypt(data).decode().split(" ", 1)

			if (msg[0] == '3317BLT5'):
			with open("/var/log/locationLog", "a") as logFile:
				date = time.localtime()
				logFile.write("{0}  {1:02} {2:02}:{3:02}:{4:02}  {6} Checking in at {5}\n".format(months[date.tm_mon - 1], date.tm_mday, date.tm_hour, date.tm_min, date.tm_sec, self.client_address[0], msg[1].strip()))
				print("[+] IP Logged to file")

			#create AES key for reply
			key = msg[1].strip()[:32].center(32)
			iv = Random.new().read(AES.block_size)
			AEScipher = AES.new(key, AES.MODE_CFB, iv)

			reply = iv + AEScipher.encrypt("\t{0}\t{1:02}:{2:02}\n".format(msg[1][:5],date.tm_hour,date.tm_min))
			print("[+] Sending success message")
			
		except BaseException as e:
			print("[-] Failure: {}".format(e))
			print("[-] Sending random message")
			reply = Random.new().read(AES.block_size+13)		

		socket.sendto(reply + b"\n", self.client_address)
		print("[+] Done")

def keyGen(path):
	key = RSA.generate(2048)
	with open(path +'/python.pem','w') as privateKey:
		privateKey.write(key.exportKey('PEM'))
	with open(path+ '/python.pub', 'w') as publicKey:
		publicKey.write(key.publickey.exportKey('PEM'))

def parseArgs():
	'''Parses args using the argparse lib'''
	parser = argparse.ArgumentParser(description='Location logging server')

	parser.add_argument('-g', '--generate-keys', metavar='PATH', type=str)
	parser.add_argument('-a', '--address', nargs=1, metavar='ADDRESS', type=ip_address)
	parser.add_argument('-p', '--port', nargs=1, metavar='PORT', type=int)

	return parser.parse_args()


if __name__ == "__main__":
	HOST, PORT = "0.0.0.0", 3145

	args = parseArgs()

	#check our args and update vars accordingly
	if args.generate_keys:
		keyGen(args.generate_keys[0])
	if args.address:
		HOST = str(args.address[0])
	if args.port:
		PORT = args.port[0]

	#check if we have the private key
	if not isfile("./python.pem"):
		print("[-] Missing public key, Exiting")
		exit(-2)

	with open("./python.pem", "r") as keyFile:
		MyUDPHandler.RSAcipher = PKCS1_OAEP.new(RSA.importKey(keyFile.read()))

	server = socketserver.UDPServer((HOST, PORT), MyUDPHandler)
	server.serve_forever()
