# TR31Keyblock

Creates Ansi X9.24 TR31 key blocks taking inputs of the Key Block Protection Key (KBPK) and the clear key.

This is the java implementation of work done here https://github.com/peterfillmore/pyTR31. It was used as a starting point and the spec was eventually implemented.
Python files are also availble in the python folder in the repo and work with python 2.7.

The original python implementation is dated and incomplete (understandably as its 8 years old). 
This code implements TR31 keblock types
1.   A :VARIANT_BINDING
1.   B :TDEA KEY DERIVATION BINDING
      1. Double length 128 bits
      2. Triple length 192 bits
1.   C :TDEA KEY VARIANT BINDING
1.   D : AES KEY DERIVATION
      1. 128 bits
      2. 192 bits
      3. 256 bits

There is a validation implementation when you get an encrypted keyblock and a KBPK. It will generate all keys,  extract the clear key, generate the MAC from the enrypted block and compare it to the one received.

The Main.java has tests for the various keyblock and key length combinations and is the best place to start and step through the code to understand its inner working.

This keyblocks generated have been tested with the EFTLABS BP-tools simulator by generating the keyblock using the code and pasting the output of  (header+encryptedkey+mac) into the simulator to see if it can parse it and show you the clear key that you had encrypted.
EFTLAB BP-TOOLS was also used to generate keyblocks and used for validity testing using the code.
The samples provided in the ANSI X9 TR 31-2018 have been tested and outputs matched.

### Note : Currently optional blocks are not supported.


Useful documents to refer to 

1. [Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf)
2. [NIST SP 800-108 Recommendation for Key Derivation Using Pseudorandom Functions (Revised)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)
3. ASC X9 TR 31-2018 (purchase required from ANSI store).

