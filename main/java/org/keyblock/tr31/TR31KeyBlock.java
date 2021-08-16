package org.keyblock.tr31;

import org.javatuples.Pair;
import org.keyblock.utils.Util;

public class TR31KeyBlock extends KeyblockGenerator{


    @Override
    public String createHeader() throws Exception {
        keyBlock.append(keyBlockType.getType());
        int blocklength = 0;
        int keylength = 48;
        switch (keyBlockType) {

            case A_VARIANT:
                // header, optional blocks,encrypted key len in ascii, mac
                // encrypted keylength is length of a triple length 3 DES key (24 bytes) which
                // when transported , its in hex hence its 48
                // e.g. 1 byte 0xC1 represented as string "C1" which is 2 bytes wide.Hence 24
                // bytes is translated to 48.
                blocklength = 16 + optionalblocks + keylength + 8;

                break;
            case B_Derivation:

                blocklength = 16 + optionalblocks + keylength + 16;// #header, optional blocks,key len in ascii, mac
                break;

            default:
                break;
        }

        // # parse block length into hex
        // String strBlockLength = "%04d" % blockLength;
        keyBlock.append(Util.padleft(String.valueOf(blocklength), 4, '0'));
        keyBlock.append(KeyUsage._D0_Data_Encryption.getUsage());
        keyBlock.append(Algorithm._T_Triple_DES.getAlgorithm());
        keyBlock.append(KeyUseFor.B_Both_Encrypt_and_Decrypt.get());
        keyBlock.append("00");// version number
        keyBlock.append(Export.E_Exportable_under_trusted_key.get());
        if (optionalblocks == 0) {
            keyBlock.append("00");
        }
        keyBlock.append("00"); // reserved field
        header = keyBlock.toString();
        return header;
    }

    public static void main(String[] args) throws Exception {
        TR31KeyBlock kbGen = new TR31KeyBlock();
        kbGen.KBPK = Util.hexStringToByteArray("89E88CF7931444F334BD7547FC3F380C");// Key block protection
        kbGen.clearKey = Util.hexStringToByteArray("F039121BEC83D26B169BDCD5B22AAF8F");

        System.out.println("Input KBPK               :" + Util.bytesToHexString(kbGen.KBPK));
        System.out.println("Input clear key          :" + Util.bytesToHexString(kbGen.clearKey));
        Pair<String, String> kbPair = kbGen.generateKBkeys();
        System.out.println("Generated KBEK           :" + kbPair.getValue0());
        System.out.println("Generated KBMK           :" + kbPair.getValue1());
        System.out.println("Generated Header         :" + kbGen.createHeader());

        System.out.println("Generated Plain Text Key :" + Util.bytesToHexString(kbGen.generatePt̋KB()));

        kbGen.generateEncryptedKeyBlock();
        System.out.println("Generated Encrypted Key  :" + Util.bytesToHexString(kbGen.encryptedKey));
        System.out.println("Generated MAC            :" + Util.bytesToHexString(kbGen.mac));
        System.out.println("Final Keyblock\nHeader + encrypted key + mac\n" + Util.dumpHexString(kbGen.finalKeyBlock));

    }

}
