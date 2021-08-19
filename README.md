# TR31Keyblock
Understanding and generating Ansi X9.24 TR31 Keyblocks

Creates Ansi X9.24 TR31 key blocks taking inputs of the Key Block Protection Key (KBPK) and the clear key.

2 keys are derived from this KBPK 
1. KBEK : the key used to encrypt the key.
1. KBMK : Key used for creating the mac of the data.


This is the java implementation of work done here https://github.com/peterfillmore/pyTR31 
Those files are also availble in the python folder in the repo and work with python 2.7.

The 2 classes TR31KeyBlock and ThalesKeyblock generate the 2 flavors of the keyblock.
You can follow the code from the main methods to understand it.

This keyblocks generated have been tested with the eftlabs BP-tools simulator by generating the keyblock using the code and pasting the output of  (header+encryptedkey+mac) into the simulator to see if it can parse it and show you the clear key that you had encrypted.


Useful documents to refer to 

1. [Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf)
2. [NIST SP 800-108 Recommendation for Key Derivation Using Pseudorandom Functions (Revised)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)
3. ASC X9 TR 31-2018 (purchase required from ANSI store).

