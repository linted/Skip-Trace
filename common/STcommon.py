import logging

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