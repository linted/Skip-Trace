import logging
from Crypto.PublicKey import RSA

def configDebugLog(logFileName):
	log_file = logging.FileHandler(logFileName,mode='w')
	log_file.setLevel(logging.DEBUG)
	log_file.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

	# ERROR level or higher should be output to console as well
	log_console = logging.StreamHandler()
	log_console.setLevel(logging.ERROR)
	log_console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

	logger = logging.getLogger('main_logger')
	logger.addHandler(log_console)
	logger.addHandler(log_file)
	return logger

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

	return parser.parse_args()

if __name__ == "__main__":
	args = parseArgs()

	if args.generate_keys:
		keyGen(args.generate_keys)