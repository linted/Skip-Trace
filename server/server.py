try:
	import sys
	sys.path.append('../common')
	from STcommon import *
	import socketserver
	import time
	import sqlite3
	from os.path import isfile
	from Crypto.Cipher import PKCS1_OAEP
	from Crypto.PublicKey import RSA
	from Crypto.Cipher import AES
	from Crypto import Random
except ImportError:
	print("[-] {}, exiting".format(e))
	exit(1)

months = ["Jan", "Feb", "Mar", "Apr", "May", "June", "July", "Aug", "Sept", "Oct", "Nov", "Dec"]

class MyUDPHandler(socketserver.BaseRequestHandler):
	RSAcipher = None

	def handle(self):
		data = self.request[0]
		socket = self.request[1]

		logger.info("[ ] Recieved request")
		try:
			msg = self.RSAcipher.decrypt(data).decode().split(" ", 1)

			if (msg[0] != '3317BLT5'):
				raise BaseException("Invalid magic number")

			with open("/var/log/locationLog", "a") as logFile:
				date = time.localtime()
				logFile.write("{0}  {1:02} {2:02}:{3:02}:{4:02}  {6} Checking in at {5}\n".format(months[date.tm_mon - 1], date.tm_mday, date.tm_hour, date.tm_min, date.tm_sec, self.client_address[0], msg[1].strip()))
				logger.info("[+] IP Logged to file")
			
		except BaseException as e:
			logger.warning("[-] Failure: {}".format(e))
			reply = Random.new().read(AES.block_size+13)
			logger.info("[-] Sending random message")

		else:
			#create AES key for reply
			key = msg[1].strip()[:32].center(32)
			iv = Random.new().read(AES.block_size)
			AEScipher = AES.new(key, AES.MODE_CFB, iv)
			reply = iv + AEScipher.encrypt("\t{0}\t{1:02}:{2:02}\n".format(msg[1][:5],date.tm_hour,date.tm_min))
			logger.info("[+] Sending success message")

		finally:
			socket.sendto(reply + b"\n", self.client_address)
			logger.info("[+] Done")

def keyGen(path):
	key = RSA.generate(2048)
	with open(path +'/python.pem','wb') as privateKey:
		privateKey.write(key.exportKey('PEM'))
	with open(path+ '/python.pub', 'wb') as publicKey:
		publicKey.write(key.publickey().exportKey('PEM'))

if __name__ == "__main__":
	configDebugLog("/var/log/skip_trace.log")
	HOST, PORT = "0.0.0.0", 3145

	#check if we have the private key
	if not isfile("./python.pem"):
		logger.critical("[-] Missing public key, Exiting")
		exit(-2)

	with open("./python.pem", "r") as keyFile:
		MyUDPHandler.RSAcipher = PKCS1_OAEP.new(RSA.importKey(keyFile.read()))

	server = socketserver.UDPServer((HOST, PORT), MyUDPHandler)
	server.serve_forever()
