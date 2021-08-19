package org.keyblock.tr31;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.javatuples.Pair;
import org.keyblock.tr31.CMAC.CONSTANTS;
import org.keyblock.utils.Util;

//@formatter:off


//@formatter:on

abstract public class KeyblockGenerator {

    private static final String CRYPTP_ALGORITHM_TRIPLE_DES = "DESede";
    public static final String  DESEDE_CBC_NO_PADDING       = "DESede/CBC/NoPadding";
    public byte[]               KBPK;                                                 // Key block protection key, e.g.
                                                                                      // your KEK
                                                                                      // key
    public byte[]               clearKey;
    // MAC key
    public static byte[]        ptKeyBlock;                                           // Plain key with length prepended
                                                                                      // and padding
                                                                                      // appended.
    public static byte[]        mac;
    public KeyblockType         keyBlockType                = KeyblockType.A_KEY_VARIANT_BINDING; // A or B
    public StringBuilder        keyBlock                    = new StringBuilder();
    byte[]                      randomPadding               = { 0x0, 0x0 };

    public int                  optionalblocks              = 0;
    public String               header;
    public byte[]               finalKeyBlock;
    public byte[]               encryptedKey;
    public Pair<String, String> KBEK_KBMK_pair_fromKBPK;
    public static KeyUsage      keyUsage                    = KeyUsage._D0_DATA_ENCRYPTION;
    public static Algorithm     algorithm                   = Algorithm._T_TRIPLE_DES;
    public KeyUseFor            keyUseFor                   = KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT;
    public static Export        export                      = Export.E_EXPORTABLE_UNDER_TRUSTED_KEY;

    /**
     * Derive KBEK (encryption key) and KBMK (mac/authentication key) from KBPK
     * (protection key)
     *
     * @return
     * @throws Exception
     */
    public Pair<String, String> generateKeyPairKBEKnKBMK(byte[] kbpk) throws Exception {

        byte[] KBEK; // key derived from KBPK for encrypting the clear key
        byte[] KBMK; // derived key to MAC. generated on header_length encoded clear key

        /*@formatter:off
        +------------+          +---+
        |            +---->KBEK_1   |
        | KBPK       |              +---->KBEK
        |            +---->KBEK_2   |
        +------------+          +---+




        +------------+          +--+
        |            +---->KBMK_1  |
        | KBPK       |             +---->KBMK
        |            +---->KBMK_2  |
        +------------+          +--+
@formatter:on
*/
        switch (keyBlockType) {
            case A_KEY_VARIANT_BINDING:
                byte[] kbpkBytes = kbpk;
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
                return new Pair<>(Util.bytesToHexString(KBEK), Util.bytesToHexString(KBMK));


            case B_TDEA_KEY_DERIVATION_BINDING: {
                Pair<String, String> k1k2FromKBPK = CMAC.generateK1K2FromTDEA_KBPK(KBPK);
                System.out.println("K1 K2 Pair KBPK :" + k1k2FromKBPK);
                String key1 = k1k2FromKBPK.getValue0();
                k1k2FromKBPK.getValue1();
                String derivationConstantKBEK01 = CONSTANTS.COUNTER._01 + CONSTANTS.KEYUSAGE._0000_ENCRYPTION
                        + CONSTANTS.SEPATATOR + CONSTANTS.ALGORITHM._0000_2TDEA + CONSTANTS.KEYLENGTH._0080_2TDEA;
                byte[] KBEK_1 = CMAC.generateKeyPartForKeyblockTypeB(Util.hexStringToByteArray(derivationConstantKBEK01),
                        KBPK, key1);
                // 0200000000000080
                String derivationConstantKBEK02 = CONSTANTS.COUNTER._02 + CONSTANTS.KEYUSAGE._0000_ENCRYPTION
                        + CONSTANTS.SEPATATOR + CONSTANTS.ALGORITHM._0000_2TDEA + CONSTANTS.KEYLENGTH._0080_2TDEA;
                byte[] KBEK_2 = CMAC.generateKeyPartForKeyblockTypeB(Util.hexStringToByteArray(derivationConstantKBEK02),
                        KBPK, key1);
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                os.write(KBEK_1);
                os.write(KBEK_2);// just concatenation the 2 byte array parts
                KBEK = os.toByteArray();
                String derivationConstantKBMK01 = CONSTANTS.COUNTER._01 + CONSTANTS.KEYUSAGE._0001_MAC
                        + CONSTANTS.SEPATATOR + CONSTANTS.ALGORITHM._0000_2TDEA + CONSTANTS.KEYLENGTH._0080_2TDEA;
                byte[] KBMK_1 = CMAC.generateKeyPartForKeyblockTypeB(Util.hexStringToByteArray(derivationConstantKBMK01),
                        KBPK, key1);
                String derivationConstantKBMK02 = CONSTANTS.COUNTER._02 + CONSTANTS.KEYUSAGE._0001_MAC
                        + CONSTANTS.SEPATATOR + CONSTANTS.ALGORITHM._0000_2TDEA + CONSTANTS.KEYLENGTH._0080_2TDEA;
                byte[] KBMK_2 = CMAC.generateKeyPartForKeyblockTypeB(Util.hexStringToByteArray(derivationConstantKBMK02),
                        KBPK, key1);
                os = new ByteArrayOutputStream();
                os.write(KBMK_1);
                os.write(KBMK_2);// just concatenation the 2 byte array parts
                KBMK = os.toByteArray();
                KBEK_KBMK_pair_fromKBPK = new Pair<>(Util.bytesToHexString(KBEK), Util.bytesToHexString(KBMK));

                return KBEK_KBMK_pair_fromKBPK;

            }


            case C_TDEA_KEY_VARIANT_BINDING:
                break;
            case D_AES_KEY_DERIVATION: {

                Pair<String, String> k1k2FromKBPK = CMAC.generateK1K2FromAES_KBPK(KBPK);

                String temp = null;

                switch (KBPK.length * 8) {
                    case 128:
                        temp = CONSTANTS.ALGORITHM._0002_AES128 + CONSTANTS.KEYLENGTH._0080_AES128;
                        break;
                    case 192:
                        temp = CONSTANTS.ALGORITHM._0003_AES192 + CONSTANTS.KEYLENGTH._00C0_AES192;
                        break;
                    case 256:
                        temp = CONSTANTS.ALGORITHM._0004_AES256 + CONSTANTS.KEYLENGTH._0100_AES256;
                        break;
                    default:
                        throw new Exception("Invalid KBPK length :" + KBPK.length);

                }

                String derivationConstantKBEK01 = CONSTANTS.COUNTER._01 + CONSTANTS.KEYUSAGE._0000_ENCRYPTION
                        + CONSTANTS.SEPATATOR + temp;
                String padding = "8000000000000000";
                byte[] k2 = Util.hexStringToByteArray(k1k2FromKBPK.getValue1());
                byte[] KBEK_1 = CMAC.generateKeyPartForKeyblockTypeD(
                        Util.hexStringToByteArray(derivationConstantKBEK01 + padding), k2, KBPK);
                String derivationConstantKBEK02 = CONSTANTS.COUNTER._02 + CONSTANTS.KEYUSAGE._0000_ENCRYPTION
                        + CONSTANTS.SEPATATOR + temp;
                byte[] KBEK_2 = CMAC.generateKeyPartForKeyblockTypeD(
                        Util.hexStringToByteArray(derivationConstantKBEK02 + padding), k2, KBPK);
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                os.write(KBEK_1);
                os.write(KBEK_2);// just concatenation the 2 byte array parts
                KBEK = os.toByteArray();
                String derivationConstantKBMK01 = CONSTANTS.COUNTER._01 + CONSTANTS.KEYUSAGE._0001_MAC
                        + CONSTANTS.SEPATATOR + temp;
                byte[] KBMK_1 = CMAC.generateKeyPartForKeyblockTypeD(
                        Util.hexStringToByteArray(derivationConstantKBMK01 + padding), k2, KBPK);
                String derivationConstantKBMK02 = CONSTANTS.COUNTER._02 + CONSTANTS.KEYUSAGE._0001_MAC
                        + CONSTANTS.SEPATATOR + temp;
                byte[] KBMK_2 = CMAC.generateKeyPartForKeyblockTypeD(
                        Util.hexStringToByteArray(derivationConstantKBMK02 + padding), k2, KBPK);
                os = new ByteArrayOutputStream();
                os.write(KBMK_1);
                os.write(KBMK_2);// just concatenation the 2 byte array parts
                KBMK = os.toByteArray();
                CMAC.generateSubKeysForKBMKForCMACWithAES(KBMK);
                KBEK_KBMK_pair_fromKBPK = new Pair<>(Util.bytesToHexString(KBEK), Util.bytesToHexString(KBMK));
                return KBEK_KBMK_pair_fromKBPK;
            }


            default:
                throw new Exception("unknown keyblock type to derive keys");

        }
        return null;


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
     * generate length encoded clear key
     */
    public byte[] generateLengthEncodedClearKey() throws Exception {
        int keyLengthBits = clearKey.length * 8;
        byte[] lengthEncodedHex = Util.hexStringToByteArray(Util.padleft(Integer.toHexString(keyLengthBits), 4, '0'));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(lengthEncodedHex);
        outputStream.write(clearKey);
        // outputStream.write(randomPadding); Python code had this but it seems
        // irrelevant


        if (outputStream.toByteArray().length % CMAC.BLOCKSIZE != 0) {
            outputStream.toByteArray();
            int padLength = CMAC.BLOCKSIZE - (outputStream.toByteArray().length % CMAC.BLOCKSIZE);
            byte[] arrayZeroes = new byte[padLength];
            // this creates a byte array initialized with 0x0
            // Fill it with random bytes. Note, this will result in a different MAC value
            // being generated eveytime even when the key is the same.
            SecureRandom sr = new SecureRandom();

            for (int i = 0; i < arrayZeroes.length; i++) {
                arrayZeroes[i] = (byte) sr.nextInt(256); // random values between 0 to 255
            }
            outputStream.write(arrayZeroes);
        }

        ptKeyBlock = outputStream.toByteArray();
        return outputStream.toByteArray();

    }

    protected byte[] generateEncryptedKeyBlock() throws Exception {

        switch (keyBlockType) {
            case A_KEY_VARIANT_BINDING: {

                // IV is first 8 bytes of the header.
                byte[] iv = header.substring(0, 8)
                                  .getBytes();
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                // conver 128 bits key i.e. double length 3DES key to triple length 3DES key. K1
                // K2 K1
                byte[] tdesKey = convertToTripleLengthKey(
                        Util.hexStringToByteArray(KBEK_KBMK_pair_fromKBPK.getValue0()));

                SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, CRYPTP_ALGORITHM_TRIPLE_DES);
                Cipher cipher = Cipher.getInstance(DESEDE_CBC_NO_PADDING);
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
                encryptedKey = cipher.doFinal(generateLengthEncodedClearKey());
                // System.out.println("Encrypted Key :" + Util.bytesToHexString(encryptedKey));
                ByteArrayOutputStream dataForMacCalculation = new ByteArrayOutputStream();
                dataForMacCalculation.write(header.getBytes());
                dataForMacCalculation.write(encryptedKey);
                ByteArrayOutputStream finalKeyBlockByteStream = new ByteArrayOutputStream();
                finalKeyBlockByteStream.write(header.getBytes());
                finalKeyBlockByteStream.write(encryptedKey);
                finalKeyBlockByteStream.write(
                        CMAC.generateMACForKeyblockTypeA(dataForMacCalculation.toByteArray(),
                                Util.hexStringToByteArray(KBEK_KBMK_pair_fromKBPK.getValue1())));
                finalKeyBlock = finalKeyBlockByteStream.toByteArray();
                return finalKeyBlock;

            }
            case B_TDEA_KEY_DERIVATION_BINDING:{
                byte[] kbmk = Util.hexStringToByteArray(KBEK_KBMK_pair_fromKBPK.getValue1());
                Pair<String, String> k1k2ForKBMK = CMAC.generateK1K2FromTDEA_KBMK(kbmk);
                byte[] kbek = Util.hexStringToByteArray(KBEK_KBMK_pair_fromKBPK.getValue0());
                System.out.println("K1 K2 KBMK :" + k1k2ForKBMK);
                ByteArrayOutputStream dataForMacCalculation = new ByteArrayOutputStream();
                dataForMacCalculation.write(header.getBytes());
                dataForMacCalculation.write(generateLengthEncodedClearKey());// use plain text key
                byte[] cmac = CMAC.generateMACForKeyblockTypeB(dataForMacCalculation.toByteArray(), k1k2ForKBMK,
                        kbmk);
                byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(kbek);
                SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, "DESede");

                Cipher cipher = Cipher.getInstance(DESEDE_CBC_NO_PADDING);
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(cmac));

                encryptedKey = cipher.doFinal(ptKeyBlock);
                ByteArrayOutputStream finalKeyBlockByteStream = new ByteArrayOutputStream();
                finalKeyBlockByteStream.write(header.getBytes());
                finalKeyBlockByteStream.write(encryptedKey);
                finalKeyBlockByteStream.write(mac);
                finalKeyBlock = finalKeyBlockByteStream.toByteArray();
                return finalKeyBlock;
        }


            case C_TDEA_KEY_VARIANT_BINDING:
                break;
            case D_AES_KEY_DERIVATION: {

                byte[] kbmk = Util.hexStringToByteArray(KBEK_KBMK_pair_fromKBPK.getValue1());
                Pair<String, String> k1k2ForKBMK = CMAC.generateK1K2FromAES_KBPK(kbmk);
                byte[] kbek = Util.hexStringToByteArray(KBEK_KBMK_pair_fromKBPK.getValue0());
                Util.hexStringToByteArray(KBEK_KBMK_pair_fromKBPK.getValue0());
                System.out.println("K1 K2 KBMK :" + k1k2ForKBMK);
                ByteArrayOutputStream dataForMacCalculation = new ByteArrayOutputStream();
                dataForMacCalculation.write(header.getBytes());
                dataForMacCalculation.write(generateLengthEncodedClearKey());// use plain text key
                byte[] cmac = CMAC.generateMACForKeyblockTypeD(dataForMacCalculation.toByteArray(), k1k2ForKBMK, kbmk);
                System.out.println("CMAC : " + Util.bytesToHexString(cmac));
                byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(kbek);
                SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(cmac));

                encryptedKey = cipher.doFinal(ptKeyBlock);
                ByteArrayOutputStream finalKeyBlockByteStream = new ByteArrayOutputStream();
                finalKeyBlockByteStream.write(header.getBytes());
                finalKeyBlockByteStream.write(encryptedKey);
                finalKeyBlockByteStream.write(mac);
                finalKeyBlock = finalKeyBlockByteStream.toByteArray();
                return finalKeyBlock;
            }
            default:
                break;
        }

        throw new Exception("Unsupported key block type " + keyBlockType);



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

}
