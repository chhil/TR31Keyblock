
package org.keyblock.tr31;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.javatuples.Pair;
import org.keyblock.utils.Util;

/**
 * This is based on the CMAC Specification found at
 * https://www.govinfo.gov/content/pkg/GOVPUB-C13-f05b7969a96dff6e1fae82057f5c211d/pdf/GOVPUB-C13-f05b7969a96dff6e1fae82057f5c211d.pdf
 *
 * @author murtuzachhil
 *
 */
public class CMAC {

    public static class CONSTANTS {
        public static final class COUNTER {
            public static final String _01 = "01";
            public static final String _02 = "02";
        }

        public static final class KEYUSAGE {
            public static final String _0000_ENCRYPTION = "0000";
            public static final String _0001_MAC        = "0001";
        }

        public static final String SEPATATOR = "00";

        public static final class ALGORITHM {
            public static final String _0000_2TDEA  = "0000";
            public static final String _0001_3TDEA  = "0001";
            public static final String _0002_AES128 = "0002";
            public static final String _0003_AES192 = "0003";
            public static final String _0004_AES256 = "0004";

        }

        public static final class KEYLENGTH {

            public static final String _0080_2TDEA  = "0080";
            public static final String _00C0_3TDEA  = "00C0";
            public static final String _0080_AES128 = "0080";
            public static final String _00C0_AES192 = "00C0";
            public static final String _0100_AES256 = "0100";

        }
        /*
         * Definition of "01 0000 00 0000 0080"
         * pos0-pos1 = counter = 01 = Values of 01 and 02
         * pos2-pos5 = key usage indicator= 0000 = 0x0000 encryption 0x0001 = MAC
         * pos6-pos7 = separator = 0x00
         * pos8-pos11 = algorithm = 0000 = 0x0000 2-Key TDEA, 0x0001 = 3-Key TDE, 0x0002
         * AES 128 bit 0x0003 = AES 192 bit 0x0004 = AES 256 bit
         * pos12-pos15 = length of key generated = 0x0080 =
         * Values : 0x0080 if one 2-key TDEA key ,0x00C0 if one 3-key TDEA,0x0080 if
         * AES-128,0x00C0 if AES-192,0x0100 if one AES-256
         */

    }

    private static final String _0000000000000000_0000000000000087 = "00000000000000000000000000000087";

    private static final String _0000000000000000                  = "0000000000000000";

    private static final String _0000000000000000_0000000000000000 = "00000000000000000000000000000000";

    private static final String _00000000_0000001B = "000000000000001B";

    public static int           BLOCKSIZE                          = 8;                                 // change it to
                                                                                                        // 16 for AES

    private static final String DESEDE_CBC_NO_PADDING = "DESede/CBC/NoPadding";// CBC needs IV
    private static final String DESEDE_ECB_NO_PADDING = "DESede/ECB/NoPadding";// ECB does not need IV
    private static final String CRYPT_ALGORITHM       = "DESede";

    /**
     * <pre>
     * Steps:
    1. Let L = CIPHK(0000000000000000). Caluclate cipher using the input key and 8 bytes of 0x0
    2.   If MSB1(L) = 0, then K1 = L << 1;
         Else K1 = (L << 1) xor 000000000000001B
    3.   If MSB1(K1) = 0, then K2 = K1 << 1;
    Else K2 = (K1 << 1) xor 000000000000001B
     * </pre>
     *
     * @param key
     *            KBPK
     * @param constantData
     *            "000000000000001B" (in bytes). Its basically a 64 bit number R64 =
     *            0^59 11011 (binary).
     * @return Key Pair K1 and K2 each 8 bytes wide (equal to the block size)
     * @throws Exception
     */
    public static Pair<String, String> generateK1K2FromTDEA_KBPK(byte[] kbpk) throws Exception {

        return generateK1K2FromTDEAKey(kbpk);


    }

    public static Pair<String, String> generateK1K2FromTDEA_KBMK(byte[] kbmk) throws Exception {

        return generateK1K2FromTDEAKey(kbmk);

    }

    protected static Pair<String, String> generateK1K2FromTDEAKey(byte[] key) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Exception {
        // Subkey derivation for CMAC with TDEA
        byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, CRYPT_ALGORITHM);

        Cipher cipher = Cipher.getInstance(DESEDE_ECB_NO_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        // Step 1: the block cipher is applied to the block that consists entirely of
        // ‘0’ bits.
        byte[] result = cipher.doFinal(Util.hexStringToByteArray(_0000000000000000)); // Encrypt 0's with key,

        byte[] K1 = getSubkeyPart(_00000000_0000001B, result);// step2
        byte[] K2 = getSubkeyPart(_00000000_0000001B, K1); // step 3

        return new Pair<>(Util.bytesToHexString(K1), Util.bytesToHexString(K2));
    }

    /**
     * Keyblock type D is AES, so crypto operations are AES based
     *
     * @param key
     *            KBPK
     * @return KeyPair subkeys K1,K2
     * @throws Exception
     */
    public static Pair<String, String> generateSubKeysForKBMKForCMACWithAES(byte[] key) throws Exception {

        // byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        // Step 1: the block cipher is applied to the block that consists entirely of
        // ‘0’ bits.

        byte[] result = cipher.doFinal(Util.hexStringToByteArray(_0000000000000000_0000000000000000));

        result = Util.shiftLeft(result);
        byte[] K1 = Util.xor(Util.hexStringToByteArray(_0000000000000000_0000000000000087), result);
        String hexK1 = Util.bytesToHexString(K1);
        K1 = Util.shiftLeft(K1);

        byte[] K2 = Util.xor(Util.hexStringToByteArray(_0000000000000000_0000000000000087), K1);
        String hexK2 = Util.bytesToHexString(K2);
        return new Pair<>(hexK1, hexK2);

    }

    protected static byte[] getSubkeyPart(String constantData, byte[] result) throws Exception {
        byte[] constantDataBytes = Util.hexStringToByteArray(constantData);
        // If MSB is not 1, then K_PART is the left shifted value
        byte[] K_PART = Util.shiftLeft(result);
        if ((result[0] & 0x80) == 0x80) {// Check MSB =1 after previous left shift
            K_PART = Util.xor(constantDataBytes, K_PART);

        }
        return K_PART;
    }


    /**
     * @param derivationConstant
     * @param kbpk
     * @return
     *         A MAC which is 64 bits (8 bytes) for keyblock type B derivation
     *         method is used.
     * @throws Exception
     */
    public static byte[] generateKeyPartForKeyblockTypeB(byte[] derivationConstant, byte[] kbpk, String keyK1)
            throws Exception {

        byte[] keyK1xorDerivationConstantresult = Util.xor(Util.hexStringToByteArray(keyK1),
                derivationConstant);

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(kbpk);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, CRYPT_ALGORITHM);

        Cipher cipher = Cipher.getInstance(DESEDE_CBC_NO_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        return cipher.doFinal(keyK1xorDerivationConstantresult);

    }

    public static byte[] generateMACForKeyblockTypeB(byte[] data, Pair<String, String> k1k2OfKBMK,
            byte[] keyKBMK) throws Exception {
        // System.out.println("Data :\n" + Util.dumpHexString(data));
        byte[] endblock = getEndblock(data, k1k2OfKBMK);
        // Replace last 8 bytes of the data with the end block which has used the last 8
        // bytes to and XOR'd with appropriate K1 or K2 key of KBMK. This replaced value
        // will be fed into the TDEA encryption
        System.arraycopy(endblock, 0, data, data.length - endblock.length, endblock.length);
        // System.out.println("Endblock Changed Data :\n" + Util.dumpHexString(data));

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
        byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(keyKBMK);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, CRYPT_ALGORITHM);

        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] result = cipher.doFinal(data);
        // System.out.println("Final Data :\n" + Util.dumpHexString(result));
        if (result.length > BLOCKSIZE) {
            byte[] mac8byte = new byte[BLOCKSIZE];
            System.arraycopy(result, result.length - BLOCKSIZE, mac8byte, 0, BLOCKSIZE);
            result = mac8byte;
        }
        KeyblockGenerator.mac = result;
        return result;

    }

    /**
     * @param data
     * @param macKey
     * @return
     *         A MAC, which is 32 bits (4 bytes) if the keyblock type "A" variant
     *         method
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public static byte[] generateMACForKeyblockTypeA(byte[] data, byte[] macKey)
            throws Exception {

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(macKey);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, CRYPT_ALGORITHM);

        // PKCS5Padding just produces a bigger mac and the offset for partial just
        // changes.
        Cipher cipher = Cipher.getInstance(DESEDE_CBC_NO_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] mac = cipher.doFinal(data);
        // System.out.println("encryptedKeyBlock :" + ISOUtil.hexString(data));
        // System.out.println("Full mac :" + ISOUtil.hexString(mac));
        byte[] partialMac = new byte[4];
        System.arraycopy(mac, mac.length - BLOCKSIZE, partialMac, 0, 4);// Extracting 4 bytes
        // System.out.println("PartialMac\n" + ISOUtil.hexString(partialMac));
        KeyblockGenerator.mac = partialMac;
        return partialMac;

    }

    protected static byte[] getEndblock(byte[] message, Pair<String, String> subKeyPairK1K2) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(message);
        byte[] endblock = new byte[BLOCKSIZE];
        if (message.length % BLOCKSIZE != 0) {
            // Padding is a binary 1 followed by as many 0x0's required
            int padLen = BLOCKSIZE - (message.length % BLOCKSIZE);
            baos.write(0x80); // this is for the placing that first binary 1.
            baos.write(new byte[padLen - 1]);// array initialized by default to 0x0's
            byte[] source = baos.toByteArray();
            System.arraycopy(source, source.length - BLOCKSIZE, endblock, 0, source.length);
            // use K2 when not a divisible message
            endblock = Util.xor(Util.hexStringToByteArray(subKeyPairK1K2.getValue1()), endblock);

        }
        else {
            byte[] source = baos.toByteArray();
            System.arraycopy(source, source.length - BLOCKSIZE, endblock, 0, BLOCKSIZE);
            // use K1 when a divisible message
            endblock = Util.xor(Util.hexStringToByteArray(subKeyPairK1K2.getValue0()), endblock);
        }
        return endblock;
    }



    public static Pair<String, String> generateK1K2FromAES_KBPK(byte[] kbpk) throws Exception {

        // byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(kbpk, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        // Step 1: the block cipher is applied to the block that consists entirely of
        // ‘0’ bits.

        byte[] result = cipher.doFinal(Util.hexStringToByteArray(_0000000000000000_0000000000000000));

        result = Util.shiftLeft(result);
        byte[] K1 = Util.xor(Util.hexStringToByteArray(_0000000000000000_0000000000000087), result);
        String hexK1 = Util.bytesToHexString(K1);
        K1 = Util.shiftLeft(K1);

        byte[] K2 = Util.xor(Util.hexStringToByteArray(_0000000000000000_0000000000000087), K1);
        String hexK2 = Util.bytesToHexString(K2);
        return new Pair<>(hexK1, hexK2);

    }

    public static byte[] generateKeyPartForKeyblockTypeD(byte[] message, byte[] kPart, byte[] kbpk) throws Exception {
        // TODO Auto-generated method stub

        byte[] xorResult = Util.xor(kPart, message);

        // Diagram in ANSI spec incorrect, shows 24 bytes but its the whole KBPK
        SecretKeySpec secretKeySpec = new SecretKeySpec(kbpk, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(xorResult);

    }



    public static byte[] generateMACForKeyblockTypeD(byte[] data, Pair<String, String> k1k2OfKBMK, byte[] keyKBMK)
            throws Exception {
        // System.out.println("Data :\n" + Util.dumpHexString(data));
        byte[] endblock = getEndblock(data, k1k2OfKBMK);
        // Replace last 8 bytes of the data with the end block which has used the last 8
        // bytes to and XOR'd with appropriate K1 or K2 key of KBMK. This replaced value
        // will be fed into the TDEA encryption
        System.arraycopy(endblock, 0, data, data.length - endblock.length, endblock.length);
        // System.out.println("Endblock Changed Data :\n" + Util.dumpHexString(data));

        byte[] iv = Util.hexStringToByteArray(_0000000000000000 + _0000000000000000);
        byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(keyKBMK);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, "AES");

        // ANSI Spec is incorrect, shows usage of ECB instead of CBC
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

        byte[] result = cipher.doFinal(data);
        System.out.println("Final Data :\n" + Util.dumpHexString(result));
        if (result.length > BLOCKSIZE) {
            byte[] mac16byte = new byte[BLOCKSIZE];
            System.arraycopy(result, result.length - BLOCKSIZE, mac16byte, 0, BLOCKSIZE);
            result = mac16byte;
        }
        KeyblockGenerator.mac = result;
        return result;

    }

}
