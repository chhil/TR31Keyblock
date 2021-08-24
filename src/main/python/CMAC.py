import Crypto
from Crypto.Cipher import DES3
from Crypto.Cipher import XOR

def generateSubkeys(MACKey, constant):
	#create encrptor
	encryptor = DES3.new(MACKey, DES3.MODE_ECB) #, '\x00\x00\x00\x00\x00\x00\x00\x00')
	XORencryptor = XOR.XORCipher(constant)

	K1 = ""
	K2 = ""	
	zeros = "\x00" * 8 #8 bytes of zeros
	S = encryptor.encrypt(zeros);
	print S.encode("hex")	
	if int(S[0].encode("hex"),16) & 0x80:
		print (int(S.encode("hex"), 16))
		shiftedS = "%016X" % ((int(S.encode("hex"), 16) << 1) & 0xFFFFFFFFFFFFFFFF) 	
		K1 = XORencryptor.encrypt(shiftedS.decode("hex"))
		
	else:
		shiftedS = "%016X" % ((int(S.encode("hex"), 16) << 1) & 0xFFFFFFFFFFFFFFFF) 	
		K1 = shiftedS.decode("hex")	
	if(int(K1[0].encode("hex"),16) & 0x80):
		shiftedS = "%016X" % ((int(K1.encode("hex"), 16) << 1) & 0xFFFFFFFFFFFFFFFF) 	
		K2 = XORencryptor.encrypt(shiftedS.decode("hex"))
	else:
		shiftedS = "%016X" % ((int(K1.encode("hex"), 16) << 1) & 0xFFFFFFFFFFFFFFFF) 	
		K2 = shiftedS.decode("hex")	
	print K1.encode("hex")	
	print K2.encode("hex")	
	return K1,K2

def generateMAC(message, key):
	padding = ""
	endblock = ""	
	(K1,K2) = generateSubkeys(key, "\x00\x00\x00\x00\x00\x00\x00\x1b")	
	#print K1.encode("hex")
	#print K2.encode("hex")
	if len(message) % 8:
		padLen = 8 - (len(message) % 8)
		padding = "\x80" + ("\x00" * (padLen-1))
		message = message + padding
		endblock = message[-8:len(message)]
		XORencryptor = XOR.XORCipher(K2)
		endblock = XORencryptor.encrypt(endblock)
	else:
		endblock = message[-8:len(message)]	
		XORencryptor = XOR.XORCipher(K1)
		endblock = XORencryptor.encrypt(endblock)
	print endblock.encode("hex")
	message = message[0:-8] + endblock
	CMACencryptor = DES3.new(key, DES3.MODE_CBC, '\x00\x00\x00\x00\x00\x00\x00\x00')
	mac = CMACencryptor.encrypt(message)
	#print key.encode("hex")	
	#print message.encode("hex")	
	print mac.encode("hex")	
	#return mac	
	return mac[-8:len(mac)]
	
def verifyMAC(mac, message, key):
	calculatedMAC = generatedMAC(message, key);
	if calculatedMAC == mac:
		return true;
	else:
		return false;	

