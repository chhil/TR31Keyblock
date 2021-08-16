package org.keyblock.tr31;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
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

public class CMAC {

    private static final String DESEDE_CBC_NO_PADDING = "DESede/CBC/NoPadding";
    private static final String DESEDE_ECB_NO_PADDING = "DESede/ECB/NoPadding";
    private static final String CRYPT_ALGORITHM       = "DESede";

    public static Pair<String, String> generateSubKeys(byte[] key, byte[] constantData) throws Exception {

        byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, CRYPT_ALGORITHM);

        Cipher cipher = Cipher.getInstance(DESEDE_ECB_NO_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] checkValue = cipher.doFinal(Util.hexStringToByteArray("0000000000000000")); // Encrypt 0's with key,
        // checkvalue
        BigInteger biK1 = new BigInteger(checkValue).shiftLeft(1);
        String checkValueLongHexStr = Long.toHexString(biK1.longValue());
        byte[] K1 = Util.hexStringToByteArray(checkValueLongHexStr);

        if ((checkValue[0] & 0x80) == 0x80) {
            K1 = Util.xor(constantData, K1);

        }
        BigInteger biK2 = new BigInteger(K1).shiftLeft(1);
        String k2LongHexStr = Long.toHexString(biK2.longValue());
        byte[] K2 = Util.hexStringToByteArray(k2LongHexStr);

        if ((K1[0] & 0x80) == 0x80) {

            K2 = Util.xor(constantData, K2);

        }

        return new Pair<>(Util.bytesToHexString(K1), Util.bytesToHexString(K2));

    }

    public static byte[] generateMACForKeyblockTypB(byte[] message, byte[] kbpk) throws Exception {

        Pair<String, String> keyPair = generateSubKeys(kbpk, Util.hexStringToByteArray("000000000000001B"));
        // System.out.println(keyPair);

        byte[] endblock = getEndblock(message, keyPair);
        System.arraycopy(endblock, 0, message, message.length - endblock.length, endblock.length);
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(kbpk);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, "DESede");

        Cipher cipher = Cipher.getInstance(DESEDE_CBC_NO_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        byte[] mac = cipher.doFinal(message);
        if (mac.length > 8) {
            byte[] mac8byte = new byte[8];
            System.arraycopy(mac, mac.length - 8, mac8byte, 0, 8);
            mac = mac8byte;
        }
        KeyblockGenerator.mac = mac;
        return mac;

    }

    public static byte[] generateMACForKeyblockTypeA(byte[] data, byte[] macKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] tdesKey = KeyblockGenerator.convertToTripleLengthKey(macKey);
        SecretKeySpec secretKeySpec = new SecretKeySpec(tdesKey, CRYPT_ALGORITHM);

        String PADDING = DESEDE_CBC_NO_PADDING;// PKCS5Padding just produces a biffer mac and the offset fpr [artial
                                               // just changes.
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        // MAC =
        // 8354df9d84cbcd3ee4ccc87d026f8bf3a90f1e1cc91aef206928d15c70487783e8041f72b0876e8e
        byte[] mac = cipher.doFinal(data);
        // System.out.println("encryptedKeyBlock :" + ISOUtil.hexString(data));
        // System.out.println("Full mac :" + ISOUtil.hexString(mac));
        byte[] partialMac = new byte[4];
        System.arraycopy(mac, mac.length - 8, partialMac, 0, 4);// K1 K2

        // System.out.println("PartialMac\n" + ISOUtil.hexString(partialMac));
        KeyblockGenerator.mac = partialMac;
        return partialMac;

    }

    protected static byte[] getEndblock(byte[] message, Pair<String, String> keyPair) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(message);
        byte[] endblock = new byte[8];
        if (message.length % 8 != 0) {

            int padLen = 8 - (message.length % 8);
            baos.write(0x80);
            baos.write(new byte[padLen - 1]);
            byte[] source = baos.toByteArray();
            System.arraycopy(source, source.length - 8, endblock, 0, source.length);
            endblock = Util.xor(Util.hexStringToByteArray(keyPair.getValue1()), endblock);

        }
        else {
            byte[] source = baos.toByteArray();
            System.arraycopy(source, source.length - 8, endblock, 0, 8);
            endblock = Util.xor(Util.hexStringToByteArray(keyPair.getValue0()), endblock);
        }
        return endblock;
    }
}
