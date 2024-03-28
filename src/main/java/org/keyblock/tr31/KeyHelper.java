package org.keyblock.tr31;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.javatuples.Pair;
import org.javatuples.Triplet;
import org.keyblock.utils.Util;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer.ResizeTransformer.Mode;

import java.security.NoSuchAlgorithmException;

/**
 * Internal stateless key related functionality.
 */
class KeyHelper {

    private KeyHelper() { }

    static final Cipher CIPHER_DES_EDE_ECB_NOPAD;
    static final Cipher CIPHER_AES_ECB_NOPAD;

    static {
        try {
            CIPHER_DES_EDE_ECB_NOPAD = Cipher.getInstance("DESede/ECB/NoPadding");
            CIPHER_AES_ECB_NOPAD = Cipher.getInstance("AES/ECB/NoPadding");
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    static Cipher getCipherForK1K2TDEAGeneration() {
        return CIPHER_DES_EDE_ECB_NOPAD;
    }

    static Cipher getCipherForK1K2AESGeneration() {
        return CIPHER_AES_ECB_NOPAD;
    }

    public static SecretKeySpec convertToTripleLengthKey(SecretKeySpec key) {
        if (key.getEncoded().length == 16) {
            // if its double length key
            // convert 128 bits key i.e. double length 3DES key to triple length 3DES 24 bit
            // key. K1 K2 K1
            byte[] tdesKey = new byte[24];
            System.arraycopy(key.getEncoded(), 0, tdesKey, 0, 16);// K1 K2 , 16 wide key = 8 bytes k1 + 8 bytes k2
            System.arraycopy(key.getEncoded(), 0, tdesKey, 16, 8); // K1 K2 K1, take the 8 bytes K1 and append it
            return new SecretKeySpec(tdesKey, key.getAlgorithm());
        }
        // its either single, triple or incorrect length
        return key;
    }

    private static Pair<Bytes, Bytes> generate192AESK1K2ForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K2,
            Pair<String, String> derivationConstantPair) throws Exception {

        Bytes result = Bytes.from(K2.xor(Bytes.parseHex(derivationConstantPair.getValue0())));
        //
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] kbek1 = cipher.doFinal(result.array());

        result = Bytes.from(K2.xor(Bytes.parseHex(derivationConstantPair.getValue1())));
        //
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] kbek2 = cipher.doFinal(result.array());

        // Since KBPK is 192, derived key must also be 192
        return new Pair<>(Bytes.from(kbek1),

                          Bytes.from(kbek2)
                               .resize(8, Mode.RESIZE_KEEP_FROM_ZERO_INDEX));

    }


    public static Pair<Bytes, Bytes> generateCMACK1K2KeysForKey(SecretKeySpec keySpec, Cipher cipher,
            byte[] intialDataToEncrypt, String derivationConstantForKey)
            throws Exception {

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        Bytes S = Bytes.from(cipher.doFinal(intialDataToEncrypt));
        Bytes K1 = S.leftShift(1);

        if ((S.byteAt(0) & 0x80) == 0x80) {
            // MSB most signinfican bit is 1
            K1 = K1.xor(Bytes.parseHex(derivationConstantForKey));

        }

        Bytes K2 = K1.leftShift(1);

        if ((K1.byteAt(0) & 0x80) == 0x80) {
            // MSB most signinfican bit is 1
            K2 = K2.xor(Bytes.parseHex(derivationConstantForKey));

        }

        return new Pair<>(K1, K2);

    }

    public static Pair<Bytes, Bytes> generate256AESK1K2ForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K2,
            Pair<String, String> derivationConstant) throws Exception {

        Bytes result = K2.xor(Bytes.parseHex(derivationConstant.getValue0()));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] keyPart1 = cipher.doFinal(result.array());
        result = K2.xor(Bytes.parseHex(derivationConstant.getValue1()));
        byte[] keyPart2 = cipher.doFinal(result.array());

        return new Pair<>(Bytes.from(keyPart1), Bytes.from(keyPart2));

    }

    public static Pair<Bytes, Bytes> generate128AESK1K2ForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K2,
            Pair<String, String> derivationConstantPair) throws Exception {

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        Bytes result = K2.xor(Bytes.parseHex(derivationConstantPair.getValue0()));
        byte[] keyPart1 = cipher.doFinal(result.array());
        // Since KBPK is 128, derived key must also be 128
        return new Pair<>(Bytes.from(keyPart1),

                          Bytes.allocate(0));

    }

    public static Triplet<Bytes, Bytes, Bytes> generate3TDEAK1K2K3ForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K1,
            Triplet<String, String, String> derivationConstantTriplet) throws Exception {

        Bytes result = K1.xor(Bytes.parseHex(derivationConstantTriplet.getValue0()));

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] keyPart1 = cipher.doFinal(result.array());

        result = K1.xor(Bytes.parseHex(derivationConstantTriplet.getValue1()));

        byte[] keyPartk2 = cipher.doFinal(result.array());

        result = K1.xor(Bytes.parseHex(derivationConstantTriplet.getValue2()));

        byte[] keyPart3 = cipher.doFinal(result.array());

        return new Triplet<>(Bytes.from(keyPart1),

                             Bytes.from(keyPartk2), Bytes.from(keyPart3));

    }

    public static Pair<Bytes, Bytes> generateK1K2keysForKey(SecretKeySpec keySpec, Cipher cipher, Bytes K1,
            Pair<String, String> derivationConstantPair) throws Exception {

        Bytes result = K1.xor(Bytes.parseHex(derivationConstantPair.getValue0()));
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] keyPart1 = cipher.doFinal(result.array());
        result = K1.xor(Bytes.parseHex(derivationConstantPair.getValue1()));
        byte[] keyPart2 = cipher.doFinal(result.array());
        return new Pair<>(Bytes.from(keyPart1), Bytes.from(keyPart2));

    }

    /**
     * Used for K1 K2 generation of KBPK and KBMK for TDES.
     */
    static String getDerivationConstantForK1K2GenerationOfKey() {
        return "000000000000001B";
    }

    /**
     * Used for K1 K2 generation of KBPK and KBMK for AES.
     */
    static String getDerivationConstantForK1K2GenerationOfAESKey() {
        return "00000000000000000000000000000087";// used for KBPK and KBMK;
    }

    public static void deriveAllKeys(TR31KeyBlock kb) throws Exception {

        switch (kb.getHeader()
                  .getKeyBlockType()) {
            case _0_THALES_DES:
                //$FALL-THROUGH$
            case _C_TDEA_KEY_VARIANT_BINDING:// Intentional fallthrough. A and C are identical;
                //$FALL-THROUGH$
            case _A_KEY_VARIANT_BINDING: {

                // To work with java crypto 128 bit double length keys are transformed to 192
                // bits triple length keys by changing k1k2 to equivalent k1k2k1 hence to get
                // the math right here we use on 128 bits of the key.

                Bytes kbpkBytes = Bytes.from(kb.getKBPK()
                                               .getEncoded());

                String E = Util.padLeft("", kbpkBytes.length(), 'E');
                String M = Util.padLeft("", kbpkBytes.length(), 'M');

                Bytes kbekBytes = kbpkBytes.xor(Bytes.from(E));
                Bytes kbmkBytes = kbpkBytes.xor(Bytes.from(M));

                // This is not needed but done to make code behavior look identical. There is no
                // need for K1 K2 as KBEK is used as.
                Pair<Bytes, Bytes> kbekPair = new Pair<>(kbekBytes.copy(0,
                        kbekBytes.length() / 2), kbekBytes.copy(kbekBytes.length() / 2, kbekBytes.length() / 2));
                Pair<Bytes, Bytes> kbmkPair = new Pair<>(kbmkBytes.copy(0,
                        kbmkBytes.length() / 2), kbmkBytes.copy(kbmkBytes.length() / 2, kbmkBytes.length() / 2));

                kb.setKeyPairK1K2KBEK(kbekPair);
                kb.setKeyPairK1K2KBMK(kbmkPair);
                break;
            }

            case _B_TDEA_KEY_DERIVATION_BINDING: {
                String derivationConstant = getDerivationConstantForK1K2GenerationOfKey();
                kb.setKeyPairCMACK1K2KBPK(generateCMACK1K2KeysForKey(kb.getKBPK(), getCipherForK1K2TDEAGeneration(),
                        new byte[8], derivationConstant));

                switch (kb.getRawKBPK().length() * 8) {
                    case 128: {// Double length TDEA key, derived KBEK and KBMK will each be 2 parts.
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
                        Pair<String, String> derivationConstantPair = kb.getDerivationConstantPair2TDEAEncryptionForKBEK();// for
                                                                                                                       // KBEK1/2
                        kb.setKeyPairK1K2KBEK(generateK1K2keysForKey(kb.getKBPK(), getCipherForK1K2TDEAGeneration(),
                                k1k2KBPK.getValue0(), derivationConstantPair));
                        derivationConstantPair = kb.getDerivationConstantPairFor2TDEAAuthenticationForKBMK();// for
                                                                                                             // KBMK1/2
                        kb.setKeyPairK1K2KBMK(generateK1K2keysForKey(kb.getKBPK(), getCipherForK1K2TDEAGeneration(),
                                k1k2KBPK.getValue0(), derivationConstantPair));
                        // generate2TDEA_K1K2_KBMK(kb); refactored to above call
                        break;
                    }
                    case 192: {// Triple length TDEA Key, derived KBEK and KBMK will each be 3 parts.
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
                        // for KBEK1/2/3
                        Triplet<String, String, String> derivationConstantTriplet = kb.getDerivationConstantTripletFor3TDEAEncryptionForKBEK();

                        kb.setKeyTripletK1K2K3KBEK(generate3TDEAK1K2K3ForKey(kb.getKBPK(),
                                getCipherForK1K2TDEAGeneration(), k1k2KBPK.getValue0(), derivationConstantTriplet));
                        // for KBMK1/2/3
                        derivationConstantTriplet = kb.getDerivationConstantTripletFor3TDEAAuthenticationForKBMK();
                        kb.setKeyTripletK1K2K3KBMK(generate3TDEAK1K2K3ForKey(kb.getKBPK(),
                                getCipherForK1K2TDEAGeneration(), k1k2KBPK.getValue0(), derivationConstantTriplet));
                        break;
                    }
                    default:
                        throw new UnsupportedOperationException("Unsupported TDES key length: " + (kb.getRawKBPK().length() * 8));
                }
                kb.setKeyPairCMACKM1KM2KBMK(generateCMACK1K2KeysForKey(kb.getKBMK(),
                        getCipherForK1K2TDEAGeneration(), new byte[8], derivationConstant));
                break;
            }

            case _1_THALES_AES:// Assumption is that Thales Keyblock type 1 and TR31 Keyblock type D are
                               // identical. The CMAC K1 K2 for KBPK seem alright as the KBEK pair derived from
                               // it encrypts the key correctly. However the K1K2KBMK or the CMACKM1KM2KBMK
                               // obtained from the K1K2KBMK is incorrect as the MAC value generatd is
                               // incorrect.
            case _D_AES_KEY_DERIVATION: {
                String derivationConstant = getDerivationConstantForK1K2GenerationOfAESKey();
                kb.setKeyPairCMACK1K2KBPK(generateCMACK1K2KeysForKey(kb.getKBPK(), getCipherForK1K2AESGeneration(),
                        new byte[16], derivationConstant));

                Cipher cipher = getCipherForK1K2AESGeneration();
                switch (kb.getRawKBPK().length() * 8) {
                    case 128: {
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
                        Pair<String, String> derivationConstantPair = kb.getDerivationConstantPairFor128AESEncryptionForKBEK();
                        kb.setKeyPairK1K2KBEK(generate128AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstantPair));// Generates KBEK 1 , KBEK2 not needed
                        derivationConstantPair = kb.getDerivationConstantPairFor128AESAuthenticationForKBMK();
                        kb.setKeyPairK1K2KBMK(generate128AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstantPair));// Generates KBMK 1 , KBMK2 not needed

                        break;
                    }
                    case 192: {
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();

                        Pair<String, String> derivationConstantPair = kb.getDerivationConstantPairFor192AESEncryptionForKBEK();

                        kb.setKeyPairK1K2KBEK(generate192AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),derivationConstantPair));// Generates KBEK 1 , KBEK2
                         derivationConstantPair = kb.getDerivationConstantPairFor192AESAuthenticationForKBMK();

                        kb.setKeyPairK1K2KBMK(generate192AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),derivationConstantPair));// Generates KBMK 1 , KBMK2
                        break;
                    }
                    case 256: {
                        Pair<Bytes, Bytes> k1k2KBPK = kb.getCMACKeyPairK1K2KBPK();
                        Pair<String, String> derivationConstantPair = kb.getDerivationConstantPairFor256AESEncryptionForKBEK();
                        kb.setKeyPairK1K2KBEK(generate256AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstantPair));// Generates KBEK 1 , KBEK2
                        derivationConstantPair = kb.getDerivationConstantPairFor256AESAuthenticationForKBMK();
                        kb.setKeyPairK1K2KBMK(generate256AESK1K2ForKey(kb.getKBPK(), cipher, k1k2KBPK.getValue1(),
                                derivationConstantPair));// Generates KBMK 1 , KBMK2
                        break;
                    }
                    default:
                        throw new UnsupportedOperationException("Unsupported AES key length: " + (kb.getRawKBPK().length() * 8));

                }

                kb.setKeyPairCMACKM1KM2KBMK(generateCMACK1K2KeysForKey(kb.getKBMK(), getCipherForK1K2AESGeneration(),
                        new byte[16], derivationConstant));
                break;
            }
            default:
                throw new Exception("Not Supported KeyBlock Type received : " + kb.getHeader().getKeyBlockType());

        }

    }

}
