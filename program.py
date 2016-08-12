import socket
import argparse
import threading
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import CAST
from Crypto.Cipher import ARC4
from Crypto.Hash import MD4
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512

"""

TODO list
- key length optamisation for CAST and ARC4 Ciphers
- Create better data exeptetion handling for all Cipher decrypters
- Create excepetion handling for bad arguments (address and protocols)

"""


def main():
	# seting argprse
	parser = argparse.ArgumentParser()
	parser.add_argument('-p', '--port', type = int, default = 5500, help = "The input port (defult is 5500)")
	parser.add_argument('-k', '--hash', type = str, default = 'SHA512', help = "Hash function for key generation (defult is SH512)")
	parser.add_argument('-c', '--cipher', type = str, default = 'AES', help = "Cipher method for Msg encryption (defult is AES)")
	parser.add_argument('address', type = str, help = "Target IP address [XYZ.XYZ.XYZ.XYZ:PORT]")
	parser.add_argument('password', type = str, help = "Your password (key) to all msgs (incoming and outcoming)")
	arguments = vars(parser.parse_args())
	
	# socket creation
	r = socket.socket()
	r.connect(('8.8.8.8',53))
	hostIP, hostPort = r.getsockname()[0], arguments['port']
	r.close()
	hostAddress = (hostIP, hostPort)
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind(hostAddress)
	
	# Hasher Creation
	if arguments['hash'] == 'SHA512':
		Hasher = SHA512.new()
	elif arguments['hash'] == 'SHA256':
		Hasher = SHA256.new()
	elif arguments['hash'] == 'MD4':
		Hasher = MD4.new()
	elif arguments['hash'] == 'MD5':
		Hasher = MD5.new()
	else:
		print("Why not Killing me?? use ctrl+c pls")
	
	# KeyCreation
	Hasher.update(arguments['password'].encode('utf-8'))
	HKEY = Hasher.digest()
	
	# Target Setting
	targetIP, targetPort = arguments['address'].split(':')
	target = (targetIP, int(targetPort))
	
	# Creating and Starting listener thread
	Reciver = netListener(arguments['port'], HKEY, arguments['cipher'], arguments['hash'], s)
	Reciver.start()
	
	# Main msg sending loop
	if arguments['cipher'] == 'AES':
		AESELoop(target, s, HKEY, hostAddress)
	elif arguments['cipher'] == 'CAST':
		CASTELoop(target, s, HKEY)
	elif arguments['cipher'] == 'ARC4':
		ARC4ELoop(target, Hasher, s, HKEY)
	else:
		print("FATAL ERROR")
		
	# breaking Listener Loop
	Reciver.kill()
	
	# ending
	return 0
	
	### MAIN LOOPS
def AESELoop(target, s, key, me):
	if len(key) < 8:
		for i in range(3):
			key += key
	if len(key) == 24:
		key = key[:16]
	if len(key) > 32:
		key = key[:32]
	print("Type --kill to end transsmition")
	while True:
		message = input("---> ")
		if message == '--kill':
			IV = Random.new().read(AES.block_size)
			s.sendto(IV + AES.new(key, AES.MODE_CFB, IV).encrypt("Listener END".encode('utf-8')),me)
			break
		elif message == '--getMyAddress':
			print("IP: {} Port {}".format(me[0],me[1]))
		else:
			raw = message.encode('utf-8')
			IV = Random.new().read(AES.block_size)
			encrypter = AES.new(key, AES.MODE_CFB, IV)
			encMsg = IV + encrypter.encrypt(raw)
			s.sendto(encMsg, target)
	
def CASTELoop(target, s, key):
	print("Type --kill to end transsmition")
	message = input("---> ")
	while message != '--kill':
		raw = message.encode('utf-8')
		IV = Random.new().read(CAST.block_size)
		encrypter = CAST.new(key, CAST.MODE_CFB, IV)
		encMsg = IV + encrypter.encrypt(raw)
		s.sendto(encMsg, target)
		message = input("---> ")

def ARC4ELoop(target, Hasher, s, key):
	print("Type --kill to end transsmition")
	message = input("---> ")
	while message != '--kill':
		raw = message.encode('utf-8')
		NONCE = Random.new().read(16)
		TmpKEY = Hasher.update(NONCE + KEY)
		encrypter = ARC4.new(TmpKEY)
		encMsg = IV + encrypter.encrypt(raw)
		s.sendto(encMsg, target)
		message = input("---> ")
	
	
	### Listener Tread
class netListener(threading.Thread):
	def __init__(self, port, key, cipher, hash, socket):
		threading.Thread.__init__(self)
		self.port = port
		self.isDead = False
		self.s = socket
		self.cipher = cipher
		self.hash = hash
		self.key = key
	
	def run(self):
		print("starting listening port " + str(self.port))
	
			# Hasher Creation
		if self.hash == 'SHA512':
			Hasher = SHA512.new()
		elif self0hash == 'SHA256':
			Hasher = SHA256.new()
		elif self.hash == 'MD4':
			Hasher = MD4.new()
		elif self.hash == 'MD5':
			Hasher = MD5.new()
		else:
			print("Why not Killing me?? use ctrl+c pls (Listener)")
		
		if self.cipher == 'AES':
			digset = 64
		elif self.cipher == 'CAST':
			Hasher.digset = 16
		elif self.cipher == 'ARC4':
			Hasher.digset = 256
		else:
			print("KILL ME PLEASE KILL ME!!!!")
		
			#Main Listener Loop
		if self.cipher == 'AES':
			self.newKey = self.key
			self.AESDecryptLoop()
		elif self.cipher == 'CAST':
			self.CASTDecryptLoop()
		elif self.cipher == 'ARC4':
			self.ARC4DecryptLoop(Hasher)
		else:
			print("FATAL ERROR")
		
	
	
	def AESDecryptLoop(self):
		# key length optamisation
		if len(self.newKey) < 8:
			for i in range(3):
				self.newKey += self.newKey
		if len(self.newKey) > 8 and len(self.newKey) < 32:
			self.newKey = self.newKey[:16]
		if len(self.newKey) > 32:
			self.newKey = self.newKey[:32]
		# Listener Loop
		while True:
			if self.isDead == True:
				break
			data, address = self.s.recvfrom(1024)
			# data length optamisation
			if len(data) < 16:
				for i in range(4):
					data += data
			# packet deformating
			IV = data[:AES.block_size]
			encMsg = data[AES.block_size:]
			# decryption
			decrypter = AES.new(self.newKey, AES.MODE_CFB, IV)
			raw = decrypter.decrypt(encMsg)
			try: # validality test
				print(str(address)+": " + raw.decode('utf-8'))
			except:
				print(str(address)+": ERROR BAD DATA")
	
	def CASTDecryptLoop(self):
		while True:
			if self.isDead == True:
				break
			data, address = self.s.recvfrom(1024)
			IV = data[:CAST.block_size]
			encMsg = data[CAST.block_size:]
			decrypter = CAST.new(self.key, CAST.MODE_CFB, IV)
			raw = decrypter.decrypt(encMsg)
			print(str(address)+": " + raw.decode('utf-8'))
	
	def ARC4DecryptLoop(self, Hasher):
		while True:
			if self.isDead == True:
				break
			data, address = self.s.recvfrom(1024)
			nonce = data[:16]
			encMsg = data[16:]
			TmpKEY = Hasher.update(nonce + self.key)
			decrypter = AES.new(TmpKEY)
			raw = decrypter.decrypt(encMsg)
			print(str(address)+": " + raw.decode('utf-8'))
	
	def kill(self):
		self.isDead = True

if __name__ == '__main__':
	main()
	s.close()
