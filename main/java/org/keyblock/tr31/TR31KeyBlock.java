package org.keyblock.tr31;

import org.javatuples.Pair;
import org.keyblock.utils.Util;

public class TR31KeyBlock extends KeyblockGenerator{


    @Override
    public String createHeader() throws Exception {
        keyBlock.append(keyBlockType.getType());
        int blocklength = 0;

        switch (keyBlockType) {

            case A_KEY_VARIANT_BINDING:
                // header, optional blocks,encrypted key len in ascii, mac
                // encrypted keylength is length of a triple length 3 DES key (24 bytes) which
                // when transported , its in hex hence its 48
                // e.g. 1 byte 0xC1 represented as string "C1" which is 2 bytes wide.Hence 24
                // bytes is translated to 48.
                blocklength = 16 + optionalblocks + 48 + 8;

                break;
            case B_TDEA_KEY_DERIVATION_BINDING:

                blocklength = 16 + optionalblocks + 48 + 16;// #header, optional blocks,key len in ascii, mac
                break;
            case C_TDEA_KEY_VARIANT_BINDING:
                break;
            case D_AES_KEY_DERIVATION:
                blocklength = 16 + optionalblocks + 64 + 32;// #header, optional blocks,key len in ascii, mac
                break;

            default:
                break;
        }

        keyBlock.append(Util.padleft(String.valueOf(blocklength), 4, '0'));
        keyBlock.append(keyUsage.getUsage());
        keyBlock.append(algorithm.getAlgorithm());
        keyBlock.append(keyUseFor.get());
        keyBlock.append("00");// version number
        keyBlock.append(export.get());
        if (optionalblocks == 0) {
            keyBlock.append("00");
        }
        keyBlock.append("00"); // reserved field
        header = keyBlock.toString();
        return header;
    }

    public static void main(String[] args) throws Exception {
        Test1();// Keyblock type B_TDEA_KEY_DERIVATION_BINDING with Double length

        Test2();
    }

    protected static void Test1() throws Exception {
        TR31KeyBlock kbGen = new TR31KeyBlock();
        CMAC.BLOCKSIZE = 8;
        kbGen.keyBlockType = KeyblockType.B_TDEA_KEY_DERIVATION_BINDING;
        // A.7.3.2.4 Derivation of the Key Block Encryption Key and Key Block
        // Authentication key
        kbGen.KBPK = Util.hexStringToByteArray("1D22BF32387C600A D97F9B97A51311AC".replace(" ", ""));

        kbGen.clearKey = Util.hexStringToByteArray("E8BC63E5479455E26577F715D587FE68");

        System.out.println("Input KBPK                      :" + Util.bytesToHexString(kbGen.KBPK));
        System.out.println("Input clear key                 :" + Util.bytesToHexString(kbGen.clearKey));
        System.out.println(
                "Generated len encoded clear key :" + Util.bytesToHexString(kbGen.generateLengthEncodedClearKey()));
        Pair<String, String> kbPair_KBEK_KBMK = kbGen.generateKeyPairKBEKnKBMK(kbGen.KBPK);
        System.out.println("Generated KBEK                  :" + kbPair_KBEK_KBMK.getValue0());
        System.out.println("Generated KBMK                  :" + kbPair_KBEK_KBMK.getValue1());
        System.out.println("Generated Header                :" + kbGen.createHeader());



        kbGen.generateEncryptedKeyBlock();
        System.out.println("Generated Encrypted Key  :" + Util.bytesToHexString(kbGen.encryptedKey));
        System.out.println("Generated MAC            :" + Util.bytesToHexString(kbGen.mac));
        System.out.println("Final Keyblock\nHeader + encrypted key + mac\n" + Util.dumpHexString(kbGen.finalKeyBlock));
        System.out.println("Usable :\n" + "KBPK :" + Util.bytesToHexString(kbGen.KBPK) + "\nKeyBlock :" + kbGen.header
                + Util.bytesToHexString(kbGen.encryptedKey) + Util.bytesToHexString(kbGen.mac));
        System.out.println("----------------------------");
    }

    protected static void Test2() throws Exception {
        TR31KeyBlock kbGen = new TR31KeyBlock();
        kbGen.keyBlockType = KeyblockType.D_AES_KEY_DERIVATION;
        kbGen.keyUsage = KeyUsage._P0_PIN_ENCRYPTION;
        kbGen.export = Export.E_EXPORTABLE_UNDER_TRUSTED_KEY;
        kbGen.algorithm = Algorithm._A_AES;
        kbGen.keyUseFor = KeyUseFor.E_ENCRYPT_ONLY;
        CMAC.BLOCKSIZE = 16;
        // A.7.4. Example 3: AES Key Block without optional blocks
        // 256 bit AES KBPK key
        kbGen.KBPK = Util.hexStringToByteArray(
                "88E1AB2A2E3DD38C 1FA039A536500CC8 A87AB9D62DC92C01 058FA79F44657DE6".replace(" ", ""));

        kbGen.clearKey = Util.hexStringToByteArray("3F419E1CB7079442 AA37474C2EFBF8B8".replace(" ", ""));

        System.out.println("Input KBPK                      :" + Util.bytesToHexString(kbGen.KBPK));
        System.out.println("Input clear key                 :" + Util.bytesToHexString(kbGen.clearKey));
        System.out.println(
                "Generated len encoded clear key :" + Util.bytesToHexString(kbGen.generateLengthEncodedClearKey()));
        Pair<String, String> kbPair_KBEK_KBMK = kbGen.generateKeyPairKBEKnKBMK(kbGen.KBPK);
        System.out.println("Generated KBEK                  :" + kbPair_KBEK_KBMK.getValue0());
        System.out.println("Generated KBMK                  :" + kbPair_KBEK_KBMK.getValue1());
        System.out.println("Generated Header                :" + kbGen.createHeader());

        kbGen.generateEncryptedKeyBlock();
        System.out.println("Generated Encrypted Key  :" + Util.bytesToHexString(kbGen.encryptedKey));
        System.out.println("Generated MAC            :" + Util.bytesToHexString(kbGen.mac));
        System.out.println("Final Keyblock\nHeader + encrypted key + mac\n" + Util.dumpHexString(kbGen.finalKeyBlock));
        System.out.println("Usable :\n" + "KBPK :" + Util.bytesToHexString(kbGen.KBPK) + "\nKeyBlock :" + kbGen.header
                + Util.bytesToHexString(kbGen.encryptedKey)
                + Util.bytesToHexString(kbGen.mac));
    }

}
