#Script to create TR-31 blocks
#im assuming the KBEK is a 128 bit key
#Input
#use --KBPK [key] to input the key, key is input as hex
#use --key to input the key to encrypt
#use --out [file] to generate txt file of output, otherwise dump to stdout

import sys,getopt
from Crypto.Cipher import DES3
import CMAC

#keys are encoded in string format
#if no keys are specified in the creation of the block, use the defaults from the TR31 docs

class tr31block:
    KBPK = ''
    key = ''
    KBEK = ''
    KBMK = ''
    ptKeyBlock = '' 
    def __init__(self,KBPK='\x89\xE8\x8C\xF7\x93\x14\x44\xF3\x34\xBD\x75\x47\xFC\x3F\x38\x0C',key='\xF0\x39\x12\x1B\xEC\x83\xD2\x6B\x16\x9B\xDC\xD5\xB2\x2A\xAF\x8F'):
        self.tempKeyBlock = list()
        self.finalKeyBlock = list()
        self.KBPK = KBPK
        self.key = key
        print (self.KBPK)
        print (self.key )
        self.keyBlockType = self.getKeyBlockType()
        self.generateKBkeys(self.keyBlockType)
        print (self.KBEK.encode("hex"))
        print (self.KBMK.encode("hex"))
        self.header = self.createHeader()
        #self.randomPadding = self.getRandomPadding() 
        self.ptKeyBlock = self.generatePtKB()
        print (self.ptKeyBlock.encode("hex"))
        if (self.keyBlockType == "A"):  
            self.keyIV = "".join(self.header)[0:8]
            self.encryptedKey = self.encryptKey(self.ptKeyBlock)
            self.tempKeyBlock.append(self.header)
            self.tempKeyBlock.append(self.encryptedKey)
            self.MAC = self.getMAC("".join(self.tempKeyBlock))
            self.finalKeyBlock.append(self.header)
            self.finalKeyBlock.append(self.encryptedKey.encode("hex"))    
            self.finalKeyBlock.append(self.MAC.encode("hex").upper())
            
        elif (self.keyBlockType == "B"):
            self.tempKeyBlock.append(self.header)
            self.tempKeyBlock.append(self.ptKeyBlock)
            print (self.tempKeyBlock )
            self.MAC = CMAC.generateMAC("".join(self.tempKeyBlock),self.KBMK)
            self.keyIV = self.MAC
            self.encryptedKey = self.encryptKey(self.ptKeyBlock)
            self.finalKeyBlock.append(self.header)
            self.finalKeyBlock.append(self.encryptedKey.encode("hex"))    
            self.finalKeyBlock.append(self.MAC.encode("hex").upper())
        
    def setKey(self,key):
        self.key = key
    def setKBPK(self,KBPK):
        self.KBPK = KBPK
    #def __init__(self,strKBPK):
    #    self.KBPK = strKBPK.decode("hex")
    #    generateKBkeys()

    def generateKBkeys(self, keyBlockType):
        if keyBlockType == "A": 
            for i in self.KBPK:
                self.KBEK = self.KBEK + chr(ord(i) ^ ord("E"))
                self.KBMK = self.KBMK + chr(ord(i) ^ ord("M"))
        elif keyBlockType == "B":
            KBEK_1 = CMAC.generateMAC("\x01\x00\x00\x00\x00\x00\x00\x80",self.KBPK)
            KBEK_2 = CMAC.generateMAC("\x02\x00\x00\x00\x00\x00\x00\x80",self.KBPK)
            self.KBEK = "".join(KBEK_1 + KBEK_2)
            KBMK_1 = CMAC.generateMAC("\x01\x00\x01\x00\x00\x00\x00\x80",self.KBPK)
            KBMK_2 = CMAC.generateMAC("\x02\x00\x01\x00\x00\x00\x00\x80",self.KBPK)
            self.KBMK = "".join(KBMK_1 + KBMK_2)

    def printKeys(self):
        print "[+] Input KBPK: \t",(self.KBPK.encode("hex"))
        print ("[+] Generated KBEK: \t",self.KBEK.encode("hex"))
        print ("[+] Generated KBMK: \t",self.KBMK.encode("hex"))
        print ("[+] Key to Encrypt: \t", self.key.encode("hex"))
        print ("[+] Generated Header: \t",self.header)
        print ("[+] Generated Plaintext KB: \t", self.ptKeyBlock.encode("hex"))
        print ("[+] Encrypted Key: \t", self.encryptedKey.encode("hex"))
        print ("[+] MAC Value \t: ",self.MAC.encode("hex"))
        #print "Generated Key Block(BIN): ", "".join(list(map(str, self.finalKeyBlock)))
        #print "[+] Generated Key Block: \t", "".join(self.finalKeyBlock).encode("hex")
        print ("[+] Generated Key Block: \t","".join(list(map(str, self.finalKeyBlock))).encode("hex"))
        #print(list(map(str, self.finalKeyBlock)))

    def createHeader(self,optionalblocks = 0,keylength=48):
        keyblock = list()
        keyblock.append(self.keyBlockType)
        if(self.keyBlockType == "A"): 
            blocklength = 16+optionalblocks+keylength+8 #header, optional blocks,key len in ascii, mac
        elif(self.keyBlockType == "B"):
            blocklength = 16+optionalblocks+keylength+16 #header, optional blocks,key len in ascii, mac
        #parse block length into hex
        strBlockLength = "%04d"%blocklength
        keyblock.append(strBlockLength)
        keyblock.append(self.getKeyUsage())
        keyblock.append(self.getAlgorithm())
        keyblock.append(self.getUseValues())
        keyblock.append(self.getKeyVersionNumber())
        keyblock.append(self.getExportByte())
        #update with optional block code when i want to
        if optionalblocks == 0:
            keyblock.append('00')
        keyblock.append('00') #reserved field
        return "".join(keyblock) #return keyblock as a string

    def getKeyBlockType(self):
        print ("Select Key Block Version:")
        print ("1) Type A - Variant Method")
        print ("2) Type B - Derivation Method")
        selection = raw_input("Enter a number:(default = 1): ")
        if selection == '':
            selection = '1'
        strSelection = {'1':"A",'2':"B"}[selection]
        return strSelection

    def getKeyUsage(self):
        print("Select Key Usage:")
        print("1) BDK Base Derivation Key")
        print("2) CVK Card Verification Key")
        print("3) Data Encryption")
        print("4) EMV/chip card Master Key: Application cryptograms")
        print("5) EMV/chip card Master Key: Secure Messaging for Confidentiality")
        print("6) EMV/chip card Master Key: Secure Messaging for Integrity")
        print("7) EMV/chip card Master Key: Data Authentication Code")
        print("8) EMV/chip card Master Key: Dynamic Numbers")
        print("9) EMV/chip card Master Key: Card Personalization")
        print("10)EMV/chip card Master Key: Other")
        print("11)Initialization Vector (IV)")
        print("12)Key Encryption or wrapping")
        print("13)ISO 16609 MAC algorithm 1 (using TDEA)")
        print("14)ISO 9797-1 MAC Algorithm 1")
        print("15)ISO 9797-1 MAC Algorithm 2")
        print("16)ISO 9797-1 MAC Algorithm 3")
        print("17)ISO 9797-1 MAC Algorithm 4")
        print("18)ISO 9797-1 MAC Algorithm 5")
        print("19)PIN Encryption")
        print("20)PIN verification, KPV, other algorithm")
        print("21)PIN verification, IBM 3624")
        print("22)PIN Verification, VISA PVV")
        selection = raw_input("Enter a number:(default = 3): ")
        if selection == '':
            selection = '3'
        strReturn = {
"1":"B0","2":"C0","3":"D0","4": "E0","5":"E1","6":"E2","7":"E3","8":"E4","9":"E5","10":"E6",
"11": "I0","12": "K0","13": "M0","14": "M1","15":"M2","16":"M3","17":"M4","18":"M5","19":"P0",
"20":"V0","21":"V1","22":"V2"
}[selection]
        return strReturn

    def getAlgorithm(self):
        print ("Select Algorithm:\n")
        print ("1) AES")
        print ("2) DEA")
        print ("3) Elliptic Curve")
        print ("4) HMAC-SHA-1")
        print ("5) RSA")
        print ("6) DSA")
        print ("7) Triple DES")
        selection = raw_input("Enter a number(default = 7):")
        if selection == '':
            selection = '7'
        strReturn = {"1":"A","2":"D","3":"E","4": "H","5":"R","6":"S","7":"T"}[selection]
        return strReturn

    def getUseValues(self):
        print ("Select Value:\n")
        print ("1) Both Encrypt and Decrypt")
        print ("2) MAC Calculate (Generate or Verify)")
        print ("3) Decrypt only")
        print ("4) Encrypt only")
        print ("5) MAC Generate only")
        print ("6) No special restrictions or not applicable")
        print ("7) Signature only")
        print ("8) MAC Verify only")
        selection = raw_input("Enter a number(Default = 1):")
        print (selection) 
        if selection == "":
            selection = '1'
        strReturn = {"1":"B","2":"C","3":"D","4":"E","5":"G","6":"N","7":"S","8":"V"}[selection]
        return strReturn

    def getRandomPadding(self):
        selection = raw_input("Enter random padding value:")
        return selection
    
    def generatePtKB(self): #generate the plaintext key block
        keypacket = list()
        keyLength = len(self.key) * 8
        hexLength = int(chr(keyLength).encode("hex"))
        lengthEncoded ="%04d"%hexLength
        keypacket.append(lengthEncoded.decode("hex"))   #length 0080 is 128 bits long
        keypacket.append(self.key)
        #keypacket.append(self.randomPadding)#random crap
        if(len("".join(keypacket)) % 8): #pad with zeros if random data not long enough
            padLen = 8-(len("".join(keypacket)) % 8) 
            zeros = "\x00" * padLen
            keypacket.append(zeros) 
        return "".join(keypacket)

    #encrypts chosen key, returns encrypted value binary.
    def encryptKey(self, tempKeyBlock):
        encryptor = DES3.new(self.KBEK, DES3.MODE_CBC, self.keyIV)
        return encryptor.encrypt(tempKeyBlock)
 
    def  getKeyVersionNumber(self):
        value = raw_input("enter key version(default=00)")
        value = str(value)
        if value == '':
            value = "\x30\x30"
        elif len(value) != 2:
            raise (Exception,('Version Number must be 2 digits long'))
        return value
        
    def getMAC(self,strKeyBlock):
        #print "BLOCK="
        print strKeyBlock.encode("hex")
        encryptor = DES3.new(self.KBMK, DES3.MODE_CBC, '\x00\x00\x00\x00\x00\x00\x00\x00')
        fullMAC = encryptor.encrypt(strKeyBlock)
        print strKeyBlock.encode("hex")
        print fullMAC.encode("hex")
        partialMAC = fullMAC[-8:-4]
        print partialMAC.encode("hex")
        return partialMAC

    
    def  getKeyVersionNumber(self):
        value = raw_input("enter key version(hit enter for no version)")
        #value = str(value)
        if value == '':
            value = "\x30\x30"
            return value
        elif len(value) != 2:
            raise (Exception,('Version Number must be 2 digits long'))
        return value
        
    def getExportByte(self):
        print ("Select Value:\n")
        print ("1) Exportable under trusted key")
        print ("2) Non-exportable")
        print ("3) Sensitive, Exportable under untrusted key")
        selection = raw_input("Enter Number (default=1):")
        if selection == "":
            selection = '1' 
        strReturn = {'1':'E','2':'N','3':'S'}[selection]
        return strReturn

    def getRandomPadding(self):
        selection = raw_input("Enter random padding value: (hex values):")
        return selection.decode("hex")

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "k:p:o:h", ["KBPK=","key=","out=","help"])
        
    except getopt.GetoptError, err:
        # print help information and exit:
        print (str(err)) # will print something like "option -a not recognized"
        #usage()
        sys.exit(2)
    #verbose = False
    for o, a in opts:
        if o in ("-h", "--help"):
            print ("enter the KBPK by -k")
            print ("enter the key to encrypt by -p")
            sys.exit()
        elif o in ("-k", "--KBPK"):
            strKBPK = a.upper().decode("hex")
            if len(strKBPK) > 16:
                assert False, "KBPK"
            elif len(strKBPK) < 16:
                assert False, "Keylength too short"
            
        elif o in ("-p", "--key"):
            strKey = a.upper().decode("hex")
            if strKey == "":
                assert False, "Encryption Key not entered"
            
        elif i in ("-o","--out"):
            strFilename = a
        else:
            assert False, "unhandled option"
    strKBPK='\x89\xE8\x8C\xF7\x93\x14\x44\xF3\x34\xBD\x75\x47\xFC\x3F\x38\x0C'
    strKey='\xF0\x39\x12\x1B\xEC\x83\xD2\x6B\x16\x9B\xDC\xD5\xB2\x2A\xAF\x8F'
    myTR31Block = tr31block(strKBPK,strKey) #create TR31 block
    myTR31Block.printKeys()

if __name__ == "__main__":
    main()
