package org.keyblock.tr31;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.javatuples.Pair;
import org.keyblock.utils.Util;

abstract public class KeyblockGenerator {
    private static final String CRYPTP_ALGORITHM_TRIPLE_DES = "DESede";
    public static final String  DESEDE_CBC_NO_PADDING       = "DESede/CBC/NoPadding";
    public byte[]               KBPK;                                                 // Key block protection key, e.g.
                                                                                      // your KEK
                                                                                      // key
    public byte[]               clearKey;
    public byte[]               KBEK;                                                 // key derived from KBPK for
                                                                                      // encrypting the clear
                                                                                      // key // Key Block Encryption
    public byte[]               KBMK;                                                 // drived key to MAC // Key block
                                                                                      // MAC key
    public static byte[]        ptKeyBlock;                                           // Plain key with length prepended
                                                                                      // and padding
                                                                                      // appended.
    public static byte[]        mac;
    public KeyblockType         keyBlockType                = KeyblockType.A_VARIANT; // A or B
    public StringBuilder        keyBlock                    = new StringBuilder();
    byte[]                      randomPadding               = { 0x0, 0x0 };

    public int                  optionalblocks              = 0;
    protected String            header;
    public byte[]               finalKeyBlock;
    public byte[]               encryptedKey;

    public Pair<String, String> generateKBkeys() throws Exception {
        // Generate the derivded keys from KBPK , KBEK (keyblock encryption key) and
        // KBMK (keyblock MAC key)

        switch (keyBlockType) {
            case A_VARIANT:
                byte[] kbpkBytes = KBPK;
                byte[] kbmkBytes = new byte[kbpkBytes.length];
                byte[] kbekBytes = new byte[kbpkBytes.length];
                /*
                 * The encryption and MAC operations used different keys created by applying
                 * predefined variants to the input key block protection key. When a TR-31 key
                 * block is protected using this method, it has the value "A" (X'41') in its key
                 * block version ID field (byte 0 of the key block header).
                 */
                for (int i = 0; i < kbpkBytes.length; i++) {
                    kbekBytes[i] = (byte) (kbpkBytes[i] ^ 'E'); // 0x45 = E

                    kbmkBytes[i] = (byte) (kbpkBytes[i] ^ 'M'); // ox4D = M
                }
                KBMK = kbmkBytes;
                KBEK = kbekBytes;

                break;
            case B_Derivation:
                /*
                 * Method "B" uses an authenticated encryption scheme and cryptographic key
                 * derivation methods to produce the encryption and MAC keys.
                 */
                byte[] KBEK_1 = CMAC.generateMACForKeyblockTypeB(Util.hexStringToByteArray("0100000000000080"), KBPK);
                byte[] KBEK_2 = CMAC.generateMACForKeyblockTypeB(Util.hexStringToByteArray("0200000000000080"), KBPK);
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                os.write(KBEK_1);
                os.write(KBEK_2);// just concatenation the 2 byte array parts
                KBEK = os.toByteArray();
                byte[] KBMK_1 = CMAC.generateMACForKeyblockTypeB(Util.hexStringToByteArray("0100010000000080"), KBPK);
                byte[] KBMK_2 = CMAC.generateMACForKeyblockTypeB(Util.hexStringToByteArray("0200010000000080"), KBPK);
                os = new ByteArrayOutputStream();
                os.write(KBMK_1);
                os.write(KBMK_2);// just concatenation the 2 byte array parts
                KBMK = os.toByteArray();

                break;
            default:
                break;

        }

        return new Pair<>(Util.bytesToHexString(KBEK), Util.bytesToHexString(KBMK));
    }

    /**
     * TR31 and Thales have slightly different headers. This abstract method is to
     * override and plugin the behavior.
     *
     * @return
     * @throws Exception
     */
    abstract protected String createHeader() throws Exception;

    /*
     * generate plain text keyblock
     */
    public byte[] generatePt̋KB() throws Exception {
        int keyLengthBits = clearKey.length * 8;
        byte[] lengthEncodedHex = Util.hexStringToByteArray(Util.padleft(Integer.toHexString(keyLengthBits), 4, '0'));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(lengthEncodedHex);
        outputStream.write(clearKey);
        // outputStream.write(randomPadding); Python code had this but it seems
        // irrelevant
        if (outputStream.toByteArray().length % 8 != 0) {
            int padLength = 8 - (outputStream.toByteArray().length % 8);
            byte[] arrayZeroes = new byte[padLength];// this creates a byte array initialized with 0x0
            // Select a random byte for padding. This way the same key will be padded
            // differently resulting in a different mac. Hence safer
            SecureRandom sr = new SecureRandom();
            int randomPad = sr.nextInt(256);

            for (int i = 0; i < arrayZeroes.length; i++) {
                arrayZeroes[i] = (byte) randomPad;
            }

            outputStream.write(arrayZeroes);
        }

        ptKeyBlock = outputStream.toByteArray();
        return outputStream.toByteArray();

    }

    protected byte[] generateEncryptedKeyBlock() throws Exception {

        if (keyBlockType == KeyblockType.A_VARIANT) {
            // IV is first 8 bytes of the header.
            byte[] iv = header.substring(0, 8)
                              .getBytes();
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // conver 128 bits key i.e. double length 3DES key to triple length 3DES key. K1
            // K2 K1
            byte[] tdesKey = convertToTripleLengthKey(KBEK);

            SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, CRYPTP_ALGORITHM_TRIPLE_DES);
            Cipher cipher = Cipher.getInstance(DESEDE_CBC_NO_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
            encryptedKey = cipher.doFinal(generatePt̋KB());
            // System.out.println("Encrypted Key :" + Util.bytesToHexString(encryptedKey));
            ByteArrayOutputStream dataForMacCalculation = new ByteArrayOutputStream();
            dataForMacCalculation.write(header.getBytes());
            dataForMacCalculation.write(encryptedKey);// uses encrypted key
            ByteArrayOutputStream finalKeyBlockByteStream = new ByteArrayOutputStream();
            finalKeyBlockByteStream.write(header.getBytes());
            finalKeyBlockByteStream.write(encryptedKey);
            finalKeyBlockByteStream.write(CMAC.generateMACForKeyblockTypeA(dataForMacCalculation.toByteArray(), KBMK));
            finalKeyBlock = finalKeyBlockByteStream.toByteArray();
            return finalKeyBlock;

        }
        if (keyBlockType == KeyblockType.B_Derivation) {

            ByteArrayOutputStream dataForMacCalculation = new ByteArrayOutputStream();
            dataForMacCalculation.write(header.getBytes());
            // System.out.println(Util.bytesToHexString(generatePt̋KB()));
            dataForMacCalculation.write(generatePt̋KB());// use plain text key
            byte[] mac = CMAC.generateMACForKeyblockTypeB(dataForMacCalculation.toByteArray(), KBMK);
            ByteArrayOutputStream finalKeyBlockByteStream = new ByteArrayOutputStream();

            byte[] iv = mac;
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // conver 128 bits key i.e. double length 3DES key to triple length 3DES key. K1
            // K2 K1
            byte[] tdesKey = convertToTripleLengthKey(KBEK);

            SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, CRYPTP_ALGORITHM_TRIPLE_DES);

            Cipher cipher = Cipher.getInstance(DESEDE_CBC_NO_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

            encryptedKey = cipher.doFinal(generatePt̋KB());
            finalKeyBlockByteStream.write(header.getBytes());
            finalKeyBlockByteStream.write(encryptedKey);
            finalKeyBlockByteStream.write(mac);
            finalKeyBlock = finalKeyBlockByteStream.toByteArray();
            return finalKeyBlock;

        }
        throw new Exception("Invalid keyblock type " + keyBlockType);

    }

    public static byte[] convertToTripleLengthKey(byte[] key) {

        if (key.length == 16) {
            // if its double length key
            // convert 128 bits key i.e. double length 3DES key to triple length 3DES 24 bit
            // key. K1 K2 K1
            byte[] tdesKey = new byte[24];
            System.arraycopy(key, 0, tdesKey, 0, 16);// K1 K2 , 16 wide key = 8 bytes k1 + 8 bytes k2
            System.arraycopy(key, 0, tdesKey, 16, 8); // K1 K2 K1, take the 8 bytes K1 and append it
            return tdesKey;
        }
        // its either single, triple or incorrect length
        return key;
    }

    /*
     * This one used when Keyblock type is A
     */

}
