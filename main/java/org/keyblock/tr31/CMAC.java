package org.keyblock.tr31;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import org.javatuples.Pair;
import org.javatuples.Triplet;
import org.keyblock.utils.Util;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer.ResizeTransformer.Mode;

public class CMAC {

    private static byte[] dataToEncrypt;

    public static void generateCMACK1K2KeysForAES_KBPK(TR31KeyBlock kb) throws Exception {
        Cipher cipher = kb.getCipherForK1K2AESGeneration();
        cipher.init(Cipher.ENCRYPT_MODE, kb.getKBPK());

        dataToEncrypt = new byte[16];

        Bytes S = Bytes.from(cipher.doFinal(dataToEncrypt));

        Bytes K1 = S.leftShift(1);
        if ((S.byteAt(0) & 0x80) == 0x80) {
            // MSB most signinfican bit is 1
            K1 = K1.xor(Bytes.parseHex(kb.getDerivationConstantForK1K2GenerationOfAESKey()));

        }

        Bytes K2 = K1.leftShift(1);

        if ((K1.byteAt(0) & 0x80) == 0x80) {
            // MSB most signinfican bit is 1
            K2 = K2.xor(Bytes.parseHex(kb.getDerivationConstantForK1K2GenerationOfAESKey()));

        }

        kb.setKeyPairCMACK1K2KBPK(new Pair<>(K1, K2));

    }

    public static Pair<Bytes, Bytes> generate192AESK1K2ForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K2,
            String derivationConstant1, String derivationConstant2) throws Exception {

        Bytes result = Bytes.from(K2.xor(Bytes.parseHex(derivationConstant1)));
        //
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] kbek1 = cipher.doFinal(result.array());

        result = Bytes.from(K2.xor(Bytes.parseHex(derivationConstant2)));
        //
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] kbek2 = cipher.doFinal(result.array());

        // Since KBPK is 192, derived key must also be 192
        return new Pair<>(Bytes.from(kbek1),

                          Bytes.from(kbek2)
                               .resize(8, Mode.RESIZE_KEEP_FROM_ZERO_INDEX));

    }

    public static void generateCMACK1K2KeysForAES_KBMK(TR31KeyBlock kb) throws Exception {
        Cipher cipher = kb.getCipherForK1K2AESGeneration();
        cipher.init(Cipher.ENCRYPT_MODE, kb.getKBMK());

        dataToEncrypt = new byte[16];

        Bytes S = Bytes.from(cipher.doFinal(dataToEncrypt));

        Bytes KM1 = S.leftShift(1);
        if ((S.byteAt(0) & 0x80) == 0x80) {
            // MSB most signinfican bit is 1
            KM1 = KM1.xor(Bytes.parseHex(kb.getDerivationConstantForK1K2GenerationOfAESKey()));

        }

        Bytes KM2 = KM1.leftShift(1);

        if ((KM1.byteAt(0) & 0x80) == 0x80) {
            // MSB most signinfican bit is 1
            KM2 = KM2.xor(Bytes.parseHex(kb.getDerivationConstantForK1K2GenerationOfAESKey()));

        }

        kb.setKeyPairCMACKM1KM2KBMK(new Pair<>(KM1, KM2));

    }

    public static Pair<Bytes, Bytes> generateCMACK1K2KeysForKey(SecretKeySpec keySpec, Cipher cipher, TR31KeyBlock kb,
            byte[] intialDataToEncrypt, String derivationConstantForKey1, String derivationConstantForKey2)
            throws Exception {

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        dataToEncrypt = intialDataToEncrypt;

        Bytes S = Bytes.from(cipher.doFinal(dataToEncrypt));
        Bytes K1 = S.leftShift(1);

        if ((S.byteAt(0) & 0x80) == 0x80) {
            // MSB most signinfican bit is 1
            K1 = K1.xor(Bytes.parseHex(derivationConstantForKey1));

        }

        Bytes K2 = K1.leftShift(1);

        if ((K1.byteAt(0) & 0x80) == 0x80) {
            // MSB most signinfican bit is 1
            K2 = K2.xor(Bytes.parseHex(derivationConstantForKey2));

        }

        return new Pair<>(K1, K2);

    }

    public static Pair<Bytes, Bytes> generate256AESK1K2ForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K2,
            String derivationConstant1, String derivationConstant2) throws Exception {

        Bytes result = K2.xor(Bytes.parseHex(derivationConstant1));

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] kbek1 = cipher.doFinal(result.array());
        result = K2.xor(Bytes.parseHex(derivationConstant2));
        byte[] kbek2 = cipher.doFinal(result.array());

        return new Pair<>(Bytes.from(kbek1), Bytes.from(kbek2));

    }

    public static Pair<Bytes, Bytes> generate128AESK1K2ForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K2,
            String derivationConstant) throws Exception {

        Bytes result = Bytes.from(K2.xor(Bytes.parseHex(derivationConstant)));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] keyPart1 = cipher.doFinal(result.array());

        // Since KBPK is 128, derived key must also be 128
        return new Pair<>(Bytes.from(keyPart1),

                          Bytes.allocate(0));

    }

    public static Triplet<Bytes, Bytes, Bytes> generate3TDEAK1K2K3ForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K1,
            String derivationConstant1, String derivationConstant2, String derivationConstant3) throws Exception {

        Bytes result = K1.xor(Bytes.parseHex(derivationConstant1));

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] keyPart1 = cipher.doFinal(result.array());

        result = K1.xor(Bytes.parseHex(derivationConstant2));

        byte[] keyPartk2 = cipher.doFinal(result.array());

        result = K1.xor(Bytes.parseHex(derivationConstant3));

        byte[] keyPart3 = cipher.doFinal(result.array());

        return new Triplet<>(Bytes.from(keyPart1),

                             Bytes.from(keyPartk2), Bytes.from(keyPart3));

    }

    public static Pair<Bytes, Bytes> generateK1K2keysForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K1,
            String derivationConstant1, String derivationConstant2) throws Exception {

        Bytes result = K1.xor(Bytes.parseHex(derivationConstant1));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] keyPart1 = cipher.doFinal(result.array());
        result = K1.xor(Bytes.parseHex(derivationConstant2));
        byte[] keyPart2 = cipher.doFinal(result.array());
        return new Pair<>(Bytes.from(keyPart1), Bytes.from(keyPart2));

    }




    public static void deriveAllKeys(TR31KeyBlock kb)
            throws IllegalBlockSizeException, BadPaddingException, Exception {

        switch (kb.getHeader()
                  .getKeyBlockType()) {
            case _0_THALES_DES:
                //$FALL-THROUGH$
            case _C_TDEA_KEY_VARIANT_BINDING:// Intentional fallthrough. A and C are identical;
                //$FALL-THROUGH$
            case _A_KEY_VARIANT_BINDING:

                // To work with java crypto 128 bit double length keys are transformed to 192
                // bits triple length keys by changing k1k2 to equivalent k1k2k1 hence to get
                // the math right here we use on 128 bits of the key.

                Bytes kbpkBytes = Bytes.from(kb.getKBPK()
                                               .getEncoded());
                // .copy(0, 16);
                Bytes kbmkBytes = Bytes.allocate(kbpkBytes.length());
                Bytes kbekBytes = Bytes.allocate(kbpkBytes.length());

                String E = Util.padleft("", kbpkBytes.length(), 'E');
                String M = Util.padleft("", kbpkBytes.length(), 'M');

                kbekBytes = kbpkBytes.xor(Bytes.from(E));
                kbmkBytes = kbpkBytes.xor(Bytes.from(M));

                // This is not needed but done to make code behavior look identical. There is no
                // need for K1 K2 as KBEK is used as.
                Pair<Bytes, Bytes> kbekPair = new Pair<>(kbekBytes.copy(0,
                        kbekBytes.length() / 2), kbekBytes.copy(kbekBytes.length() / 2, kbekBytes.length() / 2));
                Pair<Bytes, Bytes> kbmkPair = new Pair<>(kbmkBytes.copy(0,
                        kbmkBytes.length() / 2), kbmkBytes.copy(kbmkBytes.length() / 2, kbmkBytes.length() / 2));

                kb.setKeyPairK1K2KBEK(kbekPair);
                kb.setKeyPairK1K2KBMK(kbmkPair);

                break;
            case _B_TDEA_KEY_DERIVATION_BINDING:
                String derivationConstant = kb.getDerivationConstantForK1K2GenerationOfKey();
                kb.setKeyPairCMACK1K2KBPK(generateCMACK1K2KeysForKey(kb.getKBPK(), kb.getCipherForK1K2TDEAGeneration(),
                        kb, new byte[8], derivationConstant, derivationConstant));

                switch (kb.getRawKBPK()
                          .length()
                        * 8) {
                    case 128: {// Double length TDEA key, derived KBEK and KBMK will each be 3 parts.
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
                        String derivationConstant1 = kb.getDerivationConstant1For2TDEAEncryptionForKBEK();// for KBEK1
                        String derivationConstant2 = kb.getDerivationConstant2For2TDEAEncryptionForKBEK();// For KBEK2
                        kb.setKeyPairK1K2KBEK(generateK1K2keysForKey(kb.getKBPK(), kb.getCipherForK1K2TDEAGeneration(),
                                k1k2KBPK.getValue0(), derivationConstant1, derivationConstant2));
                        derivationConstant1 = kb.getDerivationConstant1For2TDEAAuthenticationForKBMK();// for KBMK1
                        derivationConstant2 = kb.getDerivationConstant2For2TDEAAuthenticationForKBMK();// For KBMK2
                        kb.setKeyPairK1K2KBMK(generateK1K2keysForKey(kb.getKBPK(), kb.getCipherForK1K2TDEAGeneration(),
                                k1k2KBPK.getValue0(), derivationConstant1, derivationConstant2));
                        // generate2TDEA_K1K2_KBMK(kb); refactored to above call
                        break;
                    }
                    case 192: {// Triple length TDEA Key, derived KBEK and KBMK will each be 3 parts.
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
                        String derivationConstant1 = kb.getDerivationConstant1For3TDEAEncryptionForKBEK();// for KBEK1
                        String derivationConstant2 = kb.getDerivationConstant2For3TDEAEncryptionForKBEK();// for KBEK2
                        String derivationConstant3 = kb.getDerivationConstant3For3TDEAEncryptionForKBEK();// for KBEK3
                        kb.setKeyTripletK1K2K3KBEK(generate3TDEAK1K2K3ForKey(kb.getKBPK(),
                                kb.getCipherForK1K2TDEAGeneration(), k1k2KBPK.getValue0(), derivationConstant1,
                                derivationConstant2, derivationConstant3));// KBEK based on constants passed in
                        derivationConstant1 = kb.getDerivationConstant1For3TDEAAuthenticationForKBMK();// for KBMK1
                        derivationConstant2 = kb.getDerivationConstant2For3TDEAAuthenticationForKBMK();// for KBMK2
                        derivationConstant3 = kb.getDerivationConstant3For3TDEAAuthenticationForKBMK();// for KBMK3
                        kb.setKeyTripletK1K2K3KBMK(generate3TDEAK1K2K3ForKey(kb.getKBPK(),
                                kb.getCipherForK1K2TDEAGeneration(), k1k2KBPK.getValue0(), derivationConstant1,
                                derivationConstant2, derivationConstant3)); // KBMK based on constants pased in
                        break;
                    }
                    default:
                        break;
                }
                kb.setKeyPairCMACKM1KM2KBMK(generateCMACK1K2KeysForKey(kb.getKBMK(),
                        kb.getCipherForK1K2TDEAGeneration(), kb, new byte[8], derivationConstant, derivationConstant));
                break;

            case _D_AES_KEY_DERIVATION:
                generateCMACK1K2KeysForAES_KBPK(kb);

                Cipher cipher = kb.getCipherForK1K2AESGeneration();
                switch (kb.getRawKBPK()
                          .length()
                        * 8) {
                    case 128: {
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
                        String derivationConstant1 = kb.getDerivationConstant1For128AESEncryptionForKBEK();
                        kb.setKeyPairK1K2KBEK(generate128AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstant1));// Generates KBEK 1 , KBEK2 not needed
                        derivationConstant1 = kb.getDerivationConstant1For128AESAuthenticationForKBMK();
                        kb.setKeyPairK1K2KBMK(generate128AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstant1));// Generates KBMK 1 , KBMK2 not needed

                        break;
                    }
                    case 192: {
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
                        String derivationConstant1 = kb.getDerivationConstant1For192AESEncryptionForKBEK();
                        String derivationConstant2 = kb.getDerivationConstant2For192AESEncryptionForKBEK();
                        kb.setKeyPairK1K2KBEK(generate192AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstant1, derivationConstant2));// Generates KBEK 1 , KBEK2
                        derivationConstant1 = kb.getDerivationConstant1For192AESAuthenticationForKBMK();
                        derivationConstant2 = kb.getDerivationConstant2For192AESAuthenticationForKBMK();
                        kb.setKeyPairK1K2KBMK(generate192AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstant1, derivationConstant2));// Generates KBMK 1 , KBMK2
                        break;
                    }
                    case 256: {
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
                        String derivationConstant1 = kb.getDerivationConstant1For256AESEncryptionForKBEK();
                        String derivationConstant2 = kb.getDerivationConstant2For256AESEncryptionForKBEK();
                        kb.setKeyPairK1K2KBEK(generate256AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstant1, derivationConstant2));// Generates KBEK 1 , KBEK2
                        derivationConstant1 = kb.getDerivationConstant1For256AESAuthenticationForKBMK();
                        derivationConstant2 = kb.getDerivationConstant2For256AESAuthenticationForKBMK();
                        kb.setKeyPairK1K2KBMK(generate256AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstant1, derivationConstant2));// Generates KBMK 1 , KBMK2
                        break;
                    }
                    default:
                        break;

                }
                generateCMACK1K2KeysForAES_KBMK(kb);
                break;
            default:
                throw new Exception("Not Supported KeyBlock Type received : " + kb.getHeader()
                                                                                  .getKeyBlockType());

        }

    }



    private static void generate128AES_K1K2_KBMK(TR31KeyBlock kb) throws Exception {
        Cipher cipher = kb.getCipherForK1K2AESGeneration();
        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
        Bytes result = k1k2KBPK.getValue1()
                               .xor(Bytes.parseHex(kb.getDerivationConstant1For256AESAuthenticationForKBMK()));

        cipher.init(Cipher.ENCRYPT_MODE, kb.getKBPK());
        byte[] kbmk1 = cipher.doFinal(result.array());

        Pair<Bytes, Bytes> kbekPair = new Pair<>(Bytes.from(kbmk1),

                                                 Bytes.allocate(0));

        kb.setKeyPairK1K2KBMK(kbekPair);

    }

}
