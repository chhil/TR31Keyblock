package org.keyblock.thales;

import org.javatuples.Pair;
import org.keyblock.tr31.Algorithm;
import org.keyblock.tr31.Export;
import org.keyblock.tr31.KeyUsage;
import org.keyblock.tr31.KeyUseFor;
import org.keyblock.tr31.KeyblockGenerator;
import org.keyblock.utils.Util;

public class ThalesKeyBlockDES extends KeyblockGenerator {

    @Override
    protected String createHeader() throws Exception {
        int keylength = 48;
        int blocklength = 16 + optionalblocks + keylength + 8;
        keyBlock.append("0");// Version ID 0:Des KBPK. 1:AES KBPK
        keyBlock.append(Util.padleft(String.valueOf(blocklength), 4, '0'));
        keyBlock.append(KeyUsage._D0_DATA_ENCRYPTION.getUsage());
        keyBlock.append(Algorithm._T_TRIPLE_DES.getAlgorithm());
        keyBlock.append(KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT.get());
        keyBlock.append("00");// version number
        keyBlock.append(Export.E_EXPORTABLE_UNDER_TRUSTED_KEY.get());
        if (optionalblocks == 0) {
            keyBlock.append("00");
        }
        keyBlock.append("00"); // LMK ID
        header = keyBlock.toString();
        return header;

    }

    public static void main(String[] args) throws Exception {
        ThalesKeyBlockDES kbGen = new ThalesKeyBlockDES();
        kbGen.KBPK = Util.hexStringToByteArray("89E88CF7931444F334BD7547FC3F380C");// Key block protection
        kbGen.clearKey = Util.hexStringToByteArray("F039121BEC83D26B169BDCD5B22AAF8F");

        System.out.println("Input KBPK               :" + Util.bytesToHexString(kbGen.KBPK));
        System.out.println("Input clear key          :" + Util.bytesToHexString(kbGen.clearKey));
        Pair<String, String> kbPair_KBEK_KBMK = kbGen.generateKeyPairKBEKnKBMK(kbGen.KBPK);
        System.out.println("Generated KBEK           :" + kbPair_KBEK_KBMK.getValue0());
        System.out.println("Generated KBMK           :" + kbPair_KBEK_KBMK.getValue1());
        System.out.println("Generated Header         :" + kbGen.createHeader());

        System.out.println("Generated Plain Text Key :" + Util.bytesToHexString(kbGen.generateLengthEncodedClearKey()));

        kbGen.generateEncryptedKeyBlock();
        System.out.println("Generated Encrypted Key  :" + Util.bytesToHexString(kbGen.encryptedKey));
        System.out.println("Generated MAC            :" + Util.bytesToHexString(kbGen.mac));
        System.out.println("Final Keyblock\nHeader + encrypted key + mac\n" + Util.dumpHexString(kbGen.finalKeyBlock));

    }



}
