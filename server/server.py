try:
	import socketserver
	import time
	import sqlite3
	from os.path import isfile
	from Crypto.Cipher import PKCS1_OAEP
	from Crypto.PublicKey import RSA
	from Crypto.Cipher import AES
	from Crypto import Random
	from binascii import unhexlify
except ImportError:
	print("[-] {}, exiting".format(e))
	exit(1)

months = ["Jan", "Feb", "Mar", "Apr", "May", "June", "July", "Aug", "Sept", "Oct", "Nov", "Dec"]

class MyUDPHandler(socketserver.BaseRequestHandler):
	RSAcipher = None

	def handle(self):
		data, socket = self.request[:2]

		print("[ ] Recieved request")
		try:
			msg = self.RSAcipher.decrypt(data).decode().split("_#_", 2)

			#check for valid magic number
			if (msg[0] != '3317BLT5'):
				raise BaseException("Invalid magic number")

			#get client Name
			clientName = msg[1].strip()[:32]
			if len(clientName) == 0:
				raise ValueError("Invalid hostname size")

			#create AES key for reply
			key = unhexlify(msg[2].strip())
			if len(key) != 32:
				raise ValueError("Invalid key size")

			with open("/var/log/locationLog", "a") as logFile:
				date = time.localtime()
				logFile.write("{0}  {1:02} {2:02}:{3:02}:{4:02}  {6} Checking in at {5}\n".format(months[date.tm_mon - 1], date.tm_mday, date.tm_hour, date.tm_min, date.tm_sec, self.client_address[0], clientName))
				print("[+] IP Logged to file")

			
		except BaseException as e:
			print("[-] Failure: {}".format(e))
			reply = Random.new().read(AES.block_size+13)
			print("[-] Sending random message")

		else:
			#create AES cipher
			iv = Random.new().read(AES.block_size)
			AEScipher = AES.new(key, AES.MODE_CFB, iv)
			reply = iv + AEScipher.encrypt("\t{0}\t{1:02}:{2:02}\n".format(clientName,date.tm_hour,date.tm_min))
			print("[+] Sending success message")

		finally:
			socket.sendto(reply + b"\n", self.client_address)
			print("[+] Done")

def keyGen(path):
	key = RSA.generate(2048)
	with open(path +'/python.pem','wb') as privateKey:
		privateKey.write(key.exportKey('PEM'))
	with open(path+ '/python.pub', 'wb') as publicKey:
		publicKey.write(key.publickey().exportKey('PEM'))


if __name__ == "__main__":
	HOST, PORT = "0.0.0.0", 3145

	#check if we have the private key
	if not isfile("./python.pem"):
		print("[-] Missing public key, Exiting")
		exit(-2)

	with open("./python.pem", "r") as keyFile:
		MyUDPHandler.RSAcipher = PKCS1_OAEP.new(RSA.importKey(keyFile.read()))

	server = socketserver.UDPServer((HOST, PORT), MyUDPHandler)
	server.serve_forever()
