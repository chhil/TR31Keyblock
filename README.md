# TR31Keyblock

Creates ASC X9 TR-31 (now ANSI X9.143) key blocks taking inputs of the Key Block Protection Key (KBPK) and the clear key.

This is the Java implementation of work done here https://github.com/peterfillmore/pyTR31. It was used as a starting point and the spec was eventually implemented.
Python files are also available in the python folder in the repo and work with python 2.7.

The original python implementation is dated and incomplete (understandably, as it's 8+ years old). 

This code implements TR31 keyblock types
1.   A: VARIANT BINDING
1.   B: TDEA KEY DERIVATION BINDING
      1. Double length 128 bits KBPK
      2. Triple length 192 bits KBPK
1.   C: TDEA KEY VARIANT BINDING
1.   D: AES KEY DERIVATION
      1. 128 bits KBPK
      2. 192 bits KBPK
      3. 256 bits KBPK

And the two proprietary Thales keyblock types, which are not covered by ASC X9 TR 31
1.   0: THALES TDEA (variant binding, 32 bit MAC)
      1. Double length 128 bits KBPK
      2. Triple length 192 bits KBPK
1.   1: THALES AES (key derivation, encrypt-then-MAC, 64 bit MAC)
      1. 128 bits KBPK
      2. 192 bits KBPK
      3. 256 bits KBPK

There is a validation implementation, when you get an encrypted keyblock and a KBPK and need to validate the TR31 keyblock received. It will generate all keys for the KBPK supplied, extract the clear key from the TR31 keyblock, generate the MAC from the encrypted block and compare it to the one received.

The Main.java has tests for the various keyblock and key length combinations and is the best place to start and step through the code to understand its inner working.

This keyblocks generated have been tested with the EFTLABS BP-tools simulator by generating the keyblock using the code and pasting the output of  (header+encryptedkey+mac) into the simulator to see if it can parse it and show you the clear key that you had encrypted.
EFTLAB BP-TOOLS was also used to generate keyblocks and used for validity testing in the code.
The samples provided in the ANSI X9 TR 31-2018 have been tested and outputs matched. Every
intermediate value published in the Annex worked examples is asserted in the test suite.

Padding of the clear key uses 0x00 by default, see the padding note below.

EFTLABS tool used to be freely available, but now its licence has changed, and you need to fill out a form requesting it. I haven't received any response after filling out the form to download an updated version of their tool.

### Usecase
1. You need to receive a known TR31 keyblock from an external entity.
2. You need to send a known TR31 keyblock to an external entity.
3. Implement functionality in your HSM emulator to generate TR31 keyblock. (either you don't have access to an HSM that can do this for you or your HSM doesn't have the licences required from the vendor for this functionality.)
4. Useful for local internal testing. (Never use this in production.)

### Note :
Thales key block types 0 and 1 are proprietary and not described by ASC X9 TR 31. Their behaviour
was determined by working backwards from real key blocks produced by the vendor, and both the
wrapping and the unwrapping paths are covered by tests built from those blocks. Thales type 1
derives its keys exactly as type D does, but it protects the block encrypt-then-MAC with an AES
CMAC over the header and the encrypted key truncated to the 64 leftmost bits, which is not
interchangeable with a type D block.

### Building
`./gradlew test` runs the test suite. If the Gradle wrapper JAR is missing from your checkout,
regenerate it with `gradle wrapper` from a local Gradle install.

### Padding
The clear key is padded with 0x00 by default so that key block generation is reproducible, which
is what makes the example vectors in the tests comparable. The spec asks for random padding, and
X9.143 additionally requires padding out to the maximum key length so the length of the key being
transported is not disclosed. For anything other than testing, call
`setPaddingDataSource(new SecureRandomPaddingDataSource())` and `enforceKeyLengthObfuscationPadding()`.
EFTLAB also uses random bytes, so data will not match byte for byte between runs even when the keys
and MAC are correct.

Useful documents to refer to 

1. [Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38b.pdf)
2. [NIST SP 800-108 Recommendation for Key Derivation Using Pseudorandom Functions (Revised)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf)
3. ASC X9 TR 31-2018 (purchase required from ANSI store, now historical).
4. ANSI X9.143-2022 (purchase required from ANSI store, replaces TR-31 and latest as of 2023)

