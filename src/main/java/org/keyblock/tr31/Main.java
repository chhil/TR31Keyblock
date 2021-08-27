package org.keyblock.tr31;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.favre.lib.bytes.Bytes;

public class Main {

    /**
     * <pre>
     ********************
     *
     *
     * [2021-08-23 01:20:35 PM]
     * TR-31 Key Block: Key block decode operation finished
     ****************************************
     * KBPK: 6BF89E64F80DBC70E9D6AEB03454E6544A67F725436E3BD3
     * TR-31 Key block:
     * D0112P0TE00E00004101636D69EDAA41ACA5596D662C3AAC23A14B4305C5D0A434476F50DD68BFDA0A4EB63DC27DB6DAEA0E6AC684BABDBE
     * ----------------------------------------
     * TR-31 Header: D0112P0TE00E0000
     * ----------------------------------------
     * Version Id: D - AES Key Derivation Binding Method
     * Block Length: 0112
     * Key Usage: P0 - PIN Encryption Key
     * Algorithm: T - Triple DES
     * Mode of Use: E - Encrypt / Wrap Only
     * Key Version No.: 00
     * Exportability: E - Exportable u. a KEK (meeting req. of X9.24 Pt. 1 or 2)
     * Num. of Opt. blocks: 00
     * Reserved: 00
     * Optional Blocks:
     * TR-31 Encrypted key:
     * 4101636D69EDAA41ACA5596D662C3AAC23A14B4305C5D0A434476F50DD68BFDA
     * TR-31 MAC: 0A4EB63DC27DB6DAEA0E6AC684BABDBE
     * ----------------------------------------
     * Plain Key: 3F419E1CB7079442AA37474C2EFBF8B8
     *
     * <pre>
     *
     * @throws Exception
     */
    public static void test192AESKeyBlockTypeD() throws Exception {
        Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));
        kb.setKBPK("6BF89E64F80DBC70E9D6AEB03454E6544A67F725436E3BD3");
        kb.generate();

        System.out.println(kb);
    }

    /**
     * <pre>
    ****************************************
    KBPK:          89E88CF7931444F334BD7547FC3F380C
    TR-31 Key block:   A0072P0TE00E0000F5161ED902807AF26F1D62263644BD24D52C8D44AAEDA6D81752022B
    ----------------------------------------
    TR-31 Header:      A0072P0TE00E0000
    ----------------------------------------
    Version Id:      A - Key Variant Binding Method
    Block Length:    0072
    Key Usage:       P0 - PIN Encryption Key
    Algorithm:       T - Triple DES
    Mode of Use:     E - Encrypt / Wrap Only
    Key Version No.: 00
    Exportability:   E - Exportable u. a KEK (meeting req. of X9.24 Pt. 1 or 2)
    Num. of Opt. blocks: 00
    Reserved:        00
    Optional Blocks:
    TR-31 Encrypted key:   F5161ED902807AF26F1D62263644BD24D52C8D44AAEDA6D8
    TR-31 MAC:     1752022B
    ----------------------------------------
    Plain Key:     F039121BEC83D26B169BDCD5B22AAF8F
     * </pre>
     *
     * @throws Exception
     */
    public static void testKeyBlockTypeA() throws Exception {
        Header header = new Header(KeyblockType._A_KEY_VARIANT_BINDING, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("89E88CF7931444F3 34BD7547FC3F380C");
        kb.generate();

        System.out.println(kb);
    }

    /**
     * <pre>
    ********************


    [2021-08-23 01:08:17 PM]
    TR-31 Key Block: Key block decode operation finished
    ****************************************
    KBPK:          DD7515F2BFC17F85CE48F3CA25CB21F6
    TR-31 Key block:   B0080P0TE00E0000A2C7F59BE6B748A73A56D613E9DAFCAB38FD56EB5496120F0E16D23DF31E7CD8
    ----------------------------------------
    TR-31 Header:      B0080P0TE00E0000
    ----------------------------------------
    Version Id:      B - TDEA Key Derivation Binding Method
    Block Length:    0080
    Key Usage:       P0 - PIN Encryption Key
    Algorithm:       T - Triple DES
    Mode of Use:     E - Encrypt / Wrap Only
    Key Version No.: 00
    Exportability:   E - Exportable u. a KEK (meeting req. of X9.24 Pt. 1 or 2)
    Num. of Opt. blocks: 00
    Reserved:        00
    Optional Blocks:
    TR-31 Encrypted key:   A2C7F59BE6B748A73A56D613E9DAFCAB38FD56EB5496120F
    TR-31 MAC:     0E16D23DF31E7CD8
    ----------------------------------------
    Plain Key:     3F419E1CB7079442AA37474C2EFBF8B8
     * </pre>
     *
     * @throws Exception
     */
    public static void test2TDEAKeyBlockTypeB() throws Exception {
        //
        Header header = new Header(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);

        kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));
        kb.setKBPK("DD7515F2BFC17F85 CE48F3CA25CB21F6");
        kb.generate();
        System.out.println(kb);

    }

    /**
     * <pre>

    ********************


    [2021-08-23 01:14:17 PM]
    TR-31 Key Block: Key block decode operation finished
    ****************************************
    KBPK:          260892192061C8760BDF235E1619B057B334FED0EFA74F32
    TR-31 Key block:   B0080P0TE00E00009AFD3EC2FB89B35F6CAE8889D7777611DFE04DA850A298BFD07667601FC01825
    ----------------------------------------
    TR-31 Header:      B0080P0TE00E0000
    ----------------------------------------
    Version Id:      B - TDEA Key Derivation Binding Method
    Block Length:    0080
    Key Usage:       P0 - PIN Encryption Key
    Algorithm:       T - Triple DES
    Mode of Use:     E - Encrypt / Wrap Only
    Key Version No.: 00
    Exportability:   E - Exportable u. a KEK (meeting req. of X9.24 Pt. 1 or 2)
    Num. of Opt. blocks: 00
    Reserved:        00
    Optional Blocks:
    TR-31 Encrypted key:   9AFD3EC2FB89B35F6CAE8889D7777611DFE04DA850A298BF
    TR-31 MAC:     D07667601FC01825
    ----------------------------------------
    Plain Key:     F039121BEC83D26B169BDCD5B22AAF8F
     * </pre>
     *
     * @throws Exception
     */
    public static void test3TDEAKeyBlockTypeB() throws Exception {
        Header header = new Header(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("260892192061C8760BDF235E1619B057B334FED0EFA74F32");// triple length
        kb.generate();
        System.out.println(kb.toString());

    }

    /**
     * <pre>
    ********************


    [2021-08-23 01:10:58 PM]
    TR-31 Key Block: Key block decode operation finished
    ****************************************
    KBPK:          89E88CF7931444F334BD7547FC3F380C
    TR-31 Key block:   C0072P0TE00E00008B82F9211C29FE6DD2676D270A2256238D1144D538C390A697789361
    ----------------------------------------
    TR-31 Header:      C0072P0TE00E0000
    ----------------------------------------
    Version Id:      C - TDEA Key Variant Binding Method
    Block Length:    0072
    Key Usage:       P0 - PIN Encryption Key
    Algorithm:       T - Triple DES
    Mode of Use:     E - Encrypt / Wrap Only
    Key Version No.: 00
    Exportability:   E - Exportable u. a KEK (meeting req. of X9.24 Pt. 1 or 2)
    Num. of Opt. blocks: 00
    Reserved:        00
    Optional Blocks:
    TR-31 Encrypted key:   8B82F9211C29FE6DD2676D270A2256238D1144D538C390A6
    TR-31 MAC:     97789361
    ----------------------------------------
    Plain Key:     F039121BEC83D26B169BDCD5B22AAF8F
     * </pre>
     *
     * @throws Exception
     */
    public static void test2TDEAKeyBlockTypeC() throws Exception {
        Header header = new Header(KeyblockType._C_TDEA_KEY_VARIANT_BINDING, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("89E88CF7931444F3 34BD7547FC3F380C");// Double length
        kb.generate();
        System.out.println(kb);

    }

    /**
     * <pre>
    ********************


    [2021-08-23 01:16:23 PM]
    TR-31 Key Block: Key block decode operation finished
    ****************************************
    KBPK:          88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6
    TR-31 Key block:   D0112P0TE00E000058742769AD697DEF9FE0EAA32B222D622C0F469170702F5BE63E6DD3F50BF78859FBF437FD5CBE4508B19DAEE31A0EAB
    ----------------------------------------
    TR-31 Header:      D0112P0TE00E0000
    ----------------------------------------
    Version Id:      D - AES Key Derivation Binding Method
    Block Length:    0112
    Key Usage:       P0 - PIN Encryption Key
    Algorithm:       T - Triple DES
    Mode of Use:     E - Encrypt / Wrap Only
    Key Version No.: 00
    Exportability:   E - Exportable u. a KEK (meeting req. of X9.24 Pt. 1 or 2)
    Num. of Opt. blocks: 00
    Reserved:        00
    Optional Blocks:
    TR-31 Encrypted key:   58742769AD697DEF9FE0EAA32B222D622C0F469170702F5BE63E6DD3F50BF788
    TR-31 MAC:     59FBF437FD5CBE4508B19DAEE31A0EAB
    ----------------------------------------
    Plain Key:     3F419E1CB7079442AA37474C2EFBF8B8
     * </pre>
     *
     * @throws Exception
     */
    public static void test256AESKeyBlockTypeD() throws Exception {
        Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));// 128 bit key
        kb.setKBPK("88E1AB2A2E3DD38C 1FA039A536500CC8 A87AB9D62DC92C01 058FA79F44657DE6");// AES 256 Bit
        kb.generate();
        System.out.println(kb);

    }

    /**
     * <pre>
    ********************


    [2021-08-23 01:18:26 PM]
    TR-31 Key Block: Key block decode operation finished
    ****************************************
    KBPK:          F45185EADC5B799819DC8F4C3B58EC73
    TR-31 Key block:   D0112P0TE00E000013B674A99811C18AB8BCFB26D347F8449E68FC074858D85DC452E43910CDC2A5E9BFE75DC94415EC0A82072217D04E35
    ----------------------------------------
    TR-31 Header:      D0112P0TE00E0000
    ----------------------------------------
    Version Id:      D - AES Key Derivation Binding Method
    Block Length:    0112
    Key Usage:       P0 - PIN Encryption Key
    Algorithm:       T - Triple DES
    Mode of Use:     E - Encrypt / Wrap Only
    Key Version No.: 00
    Exportability:   E - Exportable u. a KEK (meeting req. of X9.24 Pt. 1 or 2)
    Num. of Opt. blocks: 00
    Reserved:        00
    Optional Blocks:
    TR-31 Encrypted key:   13B674A99811C18AB8BCFB26D347F8449E68FC074858D85DC452E43910CDC2A5
    TR-31 MAC:     E9BFE75DC94415EC0A82072217D04E35
    ----------------------------------------
    Plain Key:     3F419E1CB7079442AA37474C2EFBF8B8
     * </pre>
     *
     * @throws Exception
     */
    public static void test128AESKeyBlockTypeD() throws Exception {
        Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));// 128 bit key
        kb.setKBPK("F45185EADC5B799819DC8F4C3B58EC73");// AES 128 Bit
        kb.generate();
        System.out.println(kb.toString());

    }

    public static void testDecrypt() throws Exception {
        String encryptedKey = "406B2319DE34E80187C0E300FC006FE074F629FB51D128D075E26AB427C6EAD9";
        String mac = "4522DE31F3C42E6E309FF6E4134063E9";
        Bytes iv = Bytes.parseHex(mac);// The MAC calculated is used as IV
        SecretKeySpec kbek = new SecretKeySpec(Bytes.parseHex("87EB35D5A7721DFE0FDF6DBF03AC09C938AE1EF3B32B2E30")
                                                    .array(),
                                               "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, kbek, new IvParameterSpec(iv.array()));
        Bytes result = Bytes.from(cipher.doFinal(Bytes.parseHex(encryptedKey)
                                                      .array()));
        System.out.println(result.encodeHex(true));
        System.out.println("Clear : " + "3F419E1CB7079442AA37474C2EFBF8B8");
    }

    /**
     * Takes in an encrypted keyblock and KBPK.
     *
     * @throws Exception
     */
    public static void decryptAndValidate() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        String keyBlock = "D0112P0TE00E00004101636D69EDAA41ACA5596D662C3AAC23A14B4305C5D0A434476F50DD68BFDA0A4EB63DC27DB6DAEA0E6AC684BABDBE";
        String kbpkString = "6BF89E64F80DBC70E9D6AEB03454E6544A67F725436E3BD3";
        if (kb.decryptAndValidateEncryptedKeyblock(keyBlock, kbpkString)) {
            System.out.println("VALID");
        }
        else {
            System.out.println("INVALID");
        }

    }

    public static void eftLabEncryptedBlockTest() throws Exception {

        TR31KeyBlock kb = new TR31KeyBlock();
        String keyBlock = "D0112P0TE00E000080B11B4CB23ACCB5951749D23FD2C524E9090342E56D1CAE3D43CDC5AE83C4490C27A6A8129F787C91184CE6AE6FC3A6";
        String kbpkString = "6BF89E64F80DBC70E9D6AEB03454E6544A67F725436E3BD3";
        if (kb.decryptAndValidateEncryptedKeyblock(keyBlock, kbpkString)) {
            System.out.println("VALID");
        }
        else {
            System.out.println("INVALID");
        }

    }

    /**
     * <pre>
     *  Thales Key Block: Key block decode operation finished
    ****************************************
    KBPK:          89E88CF7931444F334BD7547FC3F380C
    Thales Key block:  00072P0TE00E0000F3ABE56BDCD4AA26BE0A30C7D895A9755B5FCB994EDD8E7EE627CA46
    ----------------------------------------
    Thales Header:     00072P0TE00E0000
    ----------------------------------------
    Version Id:      0 - 3DES KBPK
    Block Length:    0072
    Key Usage:       P0 - PIN Encryption Key (Generic)
    Algorithm:       T - Triple DES
    Mode of Use:     E - Encrypt only
    Key Version No.: 00
    Exportability:   E - May only be exported in a trusted key block
    Num. of Opt. blocks: 00
    LMK ID:      00
    Optional Blocks:
    Thales Encrypted key:  F3ABE56BDCD4AA26BE0A30C7D895A9755B5FCB994EDD8E7E
    Thales MAC:        E627CA46
    ----------------------------------------
    Plain Key:     F039121BEC83D26B169BDCD5B22AAF8F
     * </pre>
     *
     * @throws Exception
     */
    public static void testKeyBlockTypeThales2Des0() throws Exception {
        Header header = new Header(KeyblockType._0_THALES_DES, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("89E88CF7931444F3 34BD7547FC3F380C");// Double length DES key
        kb.generate();

        System.out.println(kb);
    }

    /**
     * <pre>
     *  Thales Key Block: Key block decode operation finished
    ****************************************
    KBPK:          D0A16D833DC225A7C29D01FDBFC4DAFE5725FB4CEFA7FEFD
    Thales Key block:  00072P0TE00E0000735CEAAEEE913F29B69FEA2B747746DDC948F4614C3CEACCE717ED21
    ----------------------------------------
    Thales Header:     00072P0TE00E0000
    ----------------------------------------
    Version Id:      0 - 3DES KBPK
    Block Length:    0072
    Key Usage:       P0 - PIN Encryption Key (Generic)
    Algorithm:       T - Triple DES
    Mode of Use:     E - Encrypt only
    Key Version No.: 00
    Exportability:   E - May only be exported in a trusted key block
    Num. of Opt. blocks: 00
    LMK ID:      00
    Optional Blocks:
    Thales Encrypted key:  735CEAAEEE913F29B69FEA2B747746DDC948F4614C3CEACC
    Thales MAC:        E717ED21
    ----------------------------------------
    Plain Key:     F039121BEC83D26B169BDCD5B22AAF8F
     * </pre>
     *
     * @throws Exception
     */
    public static void testKeyBlockTypeThales3Des0() throws Exception {
        Header header = new Header(KeyblockType._0_THALES_DES, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("D0A16D833DC225A7C29D01FDBFC4DAFE5725FB4CEFA7FEFD");// Triple length DES key
        kb.generate();

        System.out.println(kb);
    }

    public static void testKeyBlockTypeThales128AES1() throws Exception {
        Header header = new Header(KeyblockType._1_THALES_AES, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("FED02F85DF1989F76E4F15BC370764CE");// Triple length DES key
        kb.generate();

        System.out.println(kb);
    }

    public static void testKeyBlockTypeThales256AES1() throws Exception {
        Header header = new Header(KeyblockType._1_THALES_AES, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("9B71333A13F9FAE72F9D0E2DAB4AD6784718012F9244033F3F26A2DE0C8AA11A");// AES 256 bit /32 bytes
        kb.generate();

        System.out.println(kb);
    }

    public static void decryptAndValidateAES256KBPKeyBlockType1() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        String keyBlock = "10096P0TE00E0000CF29A901B5B5DA7028693D4BE058A7B366D3CD2F5862D94E97BCD6D9F28B414A377052CE7A04D821";
        String kbpkString = "9B71333A13F9FAE72F9D0E2DAB4AD6784718012F9244033F3F26A2DE0C8AA11A";// this is the thales
                                                                                               // test AES KBPK
        if (kb.decryptAndValidateEncryptedKeyblock(keyBlock, kbpkString)) {
            System.out.println("VALID");
        }
        else {
            System.out.println("INVALID");
        }

    }

    public static void main(String[] args) throws Exception {
        testKeyBlockTypeA();
        test2TDEAKeyBlockTypeB();
        test2TDEAKeyBlockTypeC();
        test3TDEAKeyBlockTypeB();
        test256AESKeyBlockTypeD();
        test128AESKeyBlockTypeD();
        test192AESKeyBlockTypeD();
        decryptAndValidate();
        testKeyBlockTypeThales2Des0();
        testKeyBlockTypeThales3Des0();
        // The following (All using AES keyblock 1) don't generate the correct MAC.
        // Using the eft lab to decode the keyblock shows a mac mismatch error.
        // Possibility of Generating the KMBK incorrectly or the CMAC for the KMBK
        // incorrectly. Don't have access to any specification that lists how it is
        // calculated. Currently its using the TR31 Keyblock Type D code equivalent.
        testKeyBlockTypeThales128AES1();// doesn't work
        testKeyBlockTypeThales256AES1();// doesn't work, the mac is incorrect when
        // tested with EFT Labs sim
        decryptAndValidateAES256KBPKeyBlockType1();
        //

    }
}
