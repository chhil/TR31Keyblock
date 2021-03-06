package org.keyblock.tr31;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import at.favre.lib.bytes.Bytes;

public class TR31KeyBlockTest {
    @Test
    @DisplayName("TR31 KeyBlock Type A")
    void testKeyBlockTypeA() throws Exception {
        Header header = new Header(KeyblockType._A_KEY_VARIANT_BINDING, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("89E88CF7931444F3 34BD7547FC3F380C");
        kb.generate();
        assertEquals(Bytes.parseHex("1752022B"), kb.getMessageMAC());
        assertEquals(Bytes.parseHex("F5161ED902807AF26F1D62263644BD24D52C8D44AAEDA6D8"), kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F000000000000"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("CCADC9B2D65101B671F83002"), kb.getKeyPairK1K2KBEK()
                                                                   .getValue0());
        assertEquals(Bytes.parseHex("B97A7D49CCADC9B2D65101B6"), kb.getKeyPairK1K2KBEK()
                                                                   .getValue1());
        assertEquals(Bytes.parseHex("C4A5C1BADE5909BE79F0380A"), kb.getKeyPairK1K2KBMK()
                                                                   .getValue0());
        assertEquals(Bytes.parseHex("B1727541C4A5C1BADE5909BE"), kb.getKeyPairK1K2KBMK()
                                                                   .getValue1());
        assertEquals("A0072P0TE00E0000" + "F5161ED902807AF26F1D62263644BD24D52C8D44AAEDA6D8" + "1752022B",
                kb.getHeader()
                  .toString()
                        + kb.getEncryptedKey()
                            .encodeHex(true)
                        + kb.getMessageMAC()
                            .encodeHex(true));

        System.out.println(kb);
    }

    @Test
    @DisplayName("TR31 2TDEA KBPK Keyblock type B")
    void test2TDEAKeyBlockTypeB() throws Exception {
        //
        Header header = new Header(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);

        kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));
        kb.setKBPK("DD7515F2BFC17F85 CE48F3CA25CB21F6");
        kb.generate();
        System.out.println(kb);
        assertEquals(Bytes.parseHex("0E16D23DF31E7CD8"), kb.getMessageMAC());
        assertEquals(Bytes.parseHex("A2C7F59BE6B748A73A56D613E9DAFCAB38FD56EB5496120F"), kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("00803F419E1CB7079442AA37474C2EFBF8B8000000000000"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("00803F419E1CB7079442AA37474C2EFBF8B8"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("698832F8778A7CFC"), kb.getKeyPairK1K2KBEK()
                                                           .getValue0());
        assertEquals(Bytes.parseHex("BC79559DAB07B88A"), kb.getKeyPairK1K2KBEK()
                                                           .getValue1());
        assertEquals(Bytes.parseHex("DD6CEEC1782D8453"), kb.getKeyPairK1K2KBMK()
                                                           .getValue0());
        assertEquals(Bytes.parseHex("671BF8358AF9DB47"), kb.getKeyPairK1K2KBMK()
                                                           .getValue1());
        assertEquals(Bytes.parseHex("50CAF914C079A4CC"), kb.getKeyPairCMACKM1KM2KBMK()
                                                           .getValue0());
        assertEquals(Bytes.parseHex("A195F22980F34998"), kb.getKeyPairCMACKM1KM2KBMK()
                                                           .getValue1());
        assertEquals("B0080P0TE00E0000" + "A2C7F59BE6B748A73A56D613E9DAFCAB38FD56EB5496120F" + "0E16D23DF31E7CD8",
                kb.getHeader()
                  .toString()
                        + kb.getEncryptedKey()
                            .encodeHex(true)
                        + kb.getMessageMAC()
                            .encodeHex(true));
    }

    @Test
    @DisplayName("TR31 2TDEA KBPK Keyblock type C")
    void test2TDEAKeyBlockTypeC() throws Exception {
        Header header = new Header(KeyblockType._C_TDEA_KEY_VARIANT_BINDING, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("89E88CF7931444F3 34BD7547FC3F380C");// Double length
        kb.generate();
        System.out.println(kb);
        assertEquals(Bytes.parseHex("97789361"), kb.getMessageMAC());
        assertEquals(Bytes.parseHex("8B82F9211C29FE6DD2676D270A2256238D1144D538C390A6"), kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F000000000000"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("CCADC9B2D65101B671F83002"), kb.getKeyPairK1K2KBEK()
                                                           .getValue0());
        assertEquals(Bytes.parseHex("B97A7D49CCADC9B2D65101B6"), kb.getKeyPairK1K2KBEK()
                                                           .getValue1());
        assertEquals(Bytes.parseHex("C4A5C1BADE5909BE79F0380A"), kb.getKeyPairK1K2KBMK()
                                                           .getValue0());
        assertEquals(Bytes.parseHex("B1727541C4A5C1BADE5909BE"), kb.getKeyPairK1K2KBMK()
                                                           .getValue1());
        assertEquals(null, kb.getKeyPairCMACKM1KM2KBMK());
        assertEquals(null, kb.getKeyPairCMACKM1KM2KBMK());
        assertEquals("C0072P0TE00E0000" + "8B82F9211C29FE6DD2676D270A2256238D1144D538C390A6" + "97789361",
                kb.getHeader()
                  .toString()
                        + kb.getEncryptedKey()
                            .encodeHex(true)
                        + kb.getMessageMAC()
                            .encodeHex(true));

    }

    @Test
    @DisplayName("TR31 3TDEA KBPK Keyblock type B")
    void test3TDEAKeyBlockTypeB() throws Exception {
        Header header = new Header(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("260892192061C8760BDF235E1619B057B334FED0EFA74F32");// triple length
        kb.generate();
        System.out.println(kb.toString());
        assertEquals(Bytes.parseHex("D07667601FC01825"), kb.getMessageMAC());
        assertEquals(Bytes.parseHex("9AFD3EC2FB89B35F6CAE8889D7777611DFE04DA850A298BF"), kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F000000000000"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("C663C8FBDC5E1061"), kb.getTripletK1K2K3KBEK()
                                                           .getValue0());
        assertEquals(Bytes.parseHex("12F7A014BDFC561D"), kb.getTripletK1K2K3KBEK()
                                                           .getValue1());
        assertEquals(Bytes.parseHex("913C9F522283ADE6"), kb.getTripletK1K2K3KBEK()
                                                           .getValue2());
        assertEquals(Bytes.parseHex("E157450719CC9B51"), kb.getTripletK1K2K3KBMK()
                                                           .getValue0());
        assertEquals(Bytes.parseHex("72C77B811B76DD0C"), kb.getTripletK1K2K3KBMK()
                                                           .getValue1());
        assertEquals(Bytes.parseHex("E95657F280A17E98"), kb.getTripletK1K2K3KBMK()
                                                           .getValue2());
        assertEquals(Bytes.parseHex("99DD2D20F25D2ADD"), kb.getKeyPairCMACKM1KM2KBMK()
                                                           .getValue0());
        assertEquals(Bytes.parseHex("33BA5A41E4BA55A1"), kb.getKeyPairCMACKM1KM2KBMK()
                                                           .getValue1());
        assertEquals("B0080P0TE00E0000" + "9AFD3EC2FB89B35F6CAE8889D7777611DFE04DA850A298BF" + "D07667601FC01825",
                kb.getHeader()
                  .toString()
                        + kb.getEncryptedKey()
                            .encodeHex(true)
                        + kb.getMessageMAC()
                            .encodeHex(true));

    }

    @Test
    @DisplayName("TR31 AES 256 KBPK Keyblock Type D")
    void test256AESKeyBlockTypeD() throws Exception {
        Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));// 128 bit key
        kb.setKBPK("88E1AB2A2E3DD38C 1FA039A536500CC8 A87AB9D62DC92C01 058FA79F44657DE6");// AES 256 Bit
        kb.generate();
        System.out.println(kb);
        assertEquals(Bytes.parseHex("59FBF437FD5CBE4508B19DAEE31A0EAB"), kb.getMessageMAC());
        assertEquals(Bytes.parseHex("58742769AD697DEF9FE0EAA32B222D622C0F469170702F5BE63E6DD3F50BF788"),
                kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("00803F419E1CB7079442AA37474C2EFBF8B80000000000000000000000000000"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("00803F419E1CB7079442AA37474C2EFBF8B8"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("396C9382A6E2E66A088774E1D6E46541"), kb.getKeyPairK1K2KBEK()
                                                                           .getValue0());
        assertEquals(Bytes.parseHex("F5EAD67D7204F8DD0D7AE8FDA334D3AC"), kb.getKeyPairK1K2KBEK()
                                                                           .getValue1());
        assertEquals(Bytes.parseHex("4EF24317696213840451890756757E57"), kb.getKeyPairK1K2KBMK()
                                                                           .getValue0());
        assertEquals(Bytes.parseHex("3E0673483888F9B7F9B7517827F95022"), kb.getKeyPairK1K2KBMK()
                                                                           .getValue1());
        assertEquals(Bytes.parseHex("6F5F58E826D3F9295F0E9E10B0CF8BE9"), kb.getKeyPairCMACKM1KM2KBMK()
                                                                           .getValue0());
        assertEquals(Bytes.parseHex("DEBEB1D04DA7F252BE1D3C21619F17D2"), kb.getKeyPairCMACKM1KM2KBMK()
                                                                           .getValue1());
        assertEquals(
                "D0112P0TE00E0000" + "58742769AD697DEF9FE0EAA32B222D622C0F469170702F5BE63E6DD3F50BF788"
                        + "59FBF437FD5CBE4508B19DAEE31A0EAB",
                kb.getHeader()
                  .toString()
                        + kb.getEncryptedKey()
                            .encodeHex(true)
                        + kb.getMessageMAC()
                            .encodeHex(true));

    }

    @Test
    @DisplayName("TR31 AES 128 KBPK Keyblock Type D")
    void test128AESKeyBlockTypeD() throws Exception {
        Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));// 128 bit key
        kb.setKBPK("F45185EADC5B799819DC8F4C3B58EC73");// AES 128 Bit
        kb.generate();
        System.out.println(kb.toString());
        assertEquals(Bytes.parseHex("E9BFE75DC94415EC0A82072217D04E35"), kb.getMessageMAC());
        assertEquals(Bytes.parseHex("13B674A99811C18AB8BCFB26D347F8449E68FC074858D85DC452E43910CDC2A5"),
                kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("00803F419E1CB7079442AA37474C2EFBF8B80000000000000000000000000000"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("00803F419E1CB7079442AA37474C2EFBF8B8"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("2657D720B25F298BA0FAAB0C43E3DCCE"), kb.getKeyPairK1K2KBEK()
                                                                           .getValue0());
        assertEquals(Bytes.allocate(0), kb.getKeyPairK1K2KBEK()
                                          .getValue1());
        assertEquals(Bytes.parseHex("BAF9A76EFEF0FC7F594A85BFAF05978C"), kb.getKeyPairK1K2KBMK()
                                                                           .getValue0());
        assertEquals(Bytes.allocate(0), kb.getKeyPairK1K2KBMK()
                                          .getValue1());
        assertEquals(Bytes.parseHex("26D35B08A0FF8E71E31F2FD53418A1B1"), kb.getKeyPairCMACKM1KM2KBMK()
                                                                           .getValue0());
        assertEquals(Bytes.parseHex("4DA6B61141FF1CE3C63E5FAA68314362"), kb.getKeyPairCMACKM1KM2KBMK()
                                                                           .getValue1());
        assertEquals(
                "D0112P0TE00E0000" + "13B674A99811C18AB8BCFB26D347F8449E68FC074858D85DC452E43910CDC2A5"
                        + "E9BFE75DC94415EC0A82072217D04E35",
                kb.getHeader()
                  .toString()
                        + kb.getEncryptedKey()
                            .encodeHex(true)
                        + kb.getMessageMAC()
                            .encodeHex(true));

    }

    @Test
    @DisplayName("TR31 AES 192 KBPK Keyblock Type D")
    void test192AESKeyBlockTypeD() throws Exception {
        Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));
        kb.setKBPK("6BF89E64F80DBC70E9D6AEB03454E6544A67F725436E3BD3");
        kb.generate();

        System.out.println(kb.toString());
        assertEquals(Bytes.parseHex("0A4EB63DC27DB6DAEA0E6AC684BABDBE"), kb.getMessageMAC());
        assertEquals(Bytes.parseHex("4101636D69EDAA41ACA5596D662C3AAC23A14B4305C5D0A434476F50DD68BFDA"),
                kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("00803F419E1CB7079442AA37474C2EFBF8B80000000000000000000000000000"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("00803F419E1CB7079442AA37474C2EFBF8B8"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("A40F353B8DF83FD22AF83D92A997F297"), kb.getKeyPairK1K2KBEK()
                                                                           .getValue0());
        assertEquals(Bytes.parseHex("08D6F812C17D2377"), kb.getKeyPairK1K2KBEK()
                                                           .getValue1());
        assertEquals(Bytes.parseHex("13E853F3D981C1B3435350257888FC9B"), kb.getKeyPairK1K2KBMK()
                                                                           .getValue0());
        assertEquals(Bytes.parseHex("DB462111CF11325A"), kb.getKeyPairK1K2KBMK()
                                                           .getValue1());
        assertEquals(Bytes.parseHex("038672E02FA25BA966E21C36877DCB54"), kb.getKeyPairCMACKM1KM2KBMK()
                                                                           .getValue0());
        assertEquals(Bytes.parseHex("070CE5C05F44B752CDC4386D0EFB96A8"), kb.getKeyPairCMACKM1KM2KBMK()
                                                                           .getValue1());
        assertEquals(
                "D0112P0TE00E0000" + "4101636D69EDAA41ACA5596D662C3AAC23A14B4305C5D0A434476F50DD68BFDA"
                        + "0A4EB63DC27DB6DAEA0E6AC684BABDBE",
                kb.getHeader()
                  .toString()
                        + kb.getEncryptedKey()
                            .encodeHex(true)
                        + kb.getMessageMAC()
                            .encodeHex(true));
    }

    @Test
    @DisplayName("Thales 2DES Keyblock type 0")
    void testKeyBlockTypeThales2Des0() throws Exception {
        Header header = new Header(KeyblockType._0_THALES_DES, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("89E88CF7931444F3 34BD7547FC3F380C");// Double length DES key
        kb.generate();
        System.out.println(kb.toString());

        System.out.println(kb.toString());
        assertEquals(Bytes.parseHex("E627CA46"), kb.getMessageMAC());
        assertEquals(Bytes.parseHex("F3ABE56BDCD4AA26BE0A30C7D895A9755B5FCB994EDD8E7E"), kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F000000000000"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("CCADC9B2D65101B671F83002"), kb.getKeyPairK1K2KBEK()
                                                                   .getValue0());
        assertEquals(Bytes.parseHex("B97A7D49CCADC9B2D65101B6"), kb.getKeyPairK1K2KBEK()
                                                                   .getValue1());
        assertEquals(Bytes.parseHex("C4A5C1BADE5909BE79F0380A"), kb.getKeyPairK1K2KBMK()
                                                                   .getValue0());
        assertEquals(Bytes.parseHex("B1727541C4A5C1BADE5909BE"), kb.getKeyPairK1K2KBMK()
                                                                   .getValue1());
        assertEquals(null, kb.getKeyPairCMACKM1KM2KBMK());

        assertEquals("00072P0TE00E0000" + "F3ABE56BDCD4AA26BE0A30C7D895A9755B5FCB994EDD8E7E" + "E627CA46",
                kb.getHeader()
                  .toString()
                        + kb.getEncryptedKey()
                            .encodeHex(true)
                        + kb.getMessageMAC()
                            .encodeHex(true));
    }

    @Test
    @DisplayName("Thales 3DES Keyblock Type 0")
    void testKeyBlockTypeThales3Des0() throws Exception {
        Header header = new Header(KeyblockType._0_THALES_DES, KeyUsage._P0_PIN_ENCRYPTION,
                                   Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                                   KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("F039121BEC83D26B169BDCD5B22AAF8F"));
        kb.setKBPK("D0A16D833DC225A7C29D01FDBFC4DAFE5725FB4CEFA7FEFD");// Triple length DES key
        kb.generate();

        System.out.println(kb);
        assertEquals(Bytes.parseHex("E717ED21"), kb.getMessageMAC());
        assertEquals(Bytes.parseHex("735CEAAEEE913F29B69FEA2B747746DDC948F4614C3CEACC"), kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F000000000000"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("95E428C6788760E287D844B8"), kb.getKeyPairK1K2KBEK()
                                                                   .getValue0());
        assertEquals(Bytes.parseHex("FA819FBB1260BE09AAE2BBB8"), kb.getKeyPairK1K2KBEK()
                                                                   .getValue1());
        assertEquals(Bytes.parseHex("9DEC20CE708F68EA8FD04CB0"), kb.getKeyPairK1K2KBMK()
                                                                   .getValue0());
        assertEquals(Bytes.parseHex("F28997B31A68B601A2EAB3B0"), kb.getKeyPairK1K2KBMK()
                                                                   .getValue1());
        assertEquals(null, kb.getKeyPairCMACKM1KM2KBMK());

        assertEquals("00072P0TE00E0000" + "735CEAAEEE913F29B69FEA2B747746DDC948F4614C3CEACC" + "E717ED21",
                kb.getHeader()
                  .toString()
                        + kb.getEncryptedKey()
                            .encodeHex(true)
                        + kb.getMessageMAC()
                            .encodeHex(true));
    }


    /**
     * Since AES 1 is not working, this test has got the key block from EFT LAB Sim
     * and we try to decrypt it and debug the issue.
     * Have fed in the same header, KBPK and clear key. The output from the EFT LAB
     * Sim is shown below. We feed in the KBPK and ENCRYPTED keyblock to determine
     * the parts of the keyblock
     *
     * <pre>
     *  KBPK:           FED02F85DF1989F76E4F15BC370764CE
    Thales Key block:  10096P0TE00E000001309DFC752C7DBE53A3480510652D7B845AF4E211F72B502D9B32AF702A64EA459DED8BE95188D9
    ----------------------------------------
    Thales Header:     10096P0TE00E0000
    ----------------------------------------
    Version Id:      1 - AES KBPK
    Block Length:    0096
    Key Usage:       P0 - PIN Encryption Key (Generic)
    Algorithm:       T - Triple DES
    Mode of Use:     E - Encrypt only
    Key Version No.: 00
    Exportability:   E - May only be exported in a trusted key block
    Num. of Opt. blocks: 00
    LMK ID:      00
    Optional Blocks:
    Thales Encrypted key:  01309DFC752C7DBE53A3480510652D7B845AF4E211F72B502D9B32AF702A64EA
    Thales MAC:        459DED8BE95188D9
    ----------------------------------------
    Plain Key:     F039121BEC83D26B169BDCD5B22AAF8F
    KCV:           CB9DEA
     * </pre>
     *
     * @throws Exception
     */
    @Test
    @DisplayName("Thales Validate AES128 KBPK keyblock type 1: test will fail for MAC mismatch")
    void decryptAndValidateAES128KeyBlockType1() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        String keyBlock = "10096P0TE00E000001309DFC752C7DBE53A3480510652D7B845AF4E211F72B502D9B32AF702A64EA459DED8BE95188D9";
        String kbpkString = "FED02F85DF1989F76E4F15BC370764CE";// this is the thales

        if (kb.decryptAndValidateEncryptedKeyblock(keyBlock, kbpkString)) {
            System.out.println("VALID");
        }
        else {
            System.out.println("INVALID");
        }
        System.out.println(kb.toString()); // test AES KBPK

        //
        assertEquals(Bytes.parseHex("01309DFC752C7DBE53A3480510652D7B845AF4E211F72B502D9B32AF702A64EA"),
                kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8FD102DC4312C4649AA966B0D10B56"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("D102DC4312C4649AA966B0D10B56"), kb.getClearKeyPadding());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("A3E44F5D04E47518F20D596FC433AC2B"), kb.getKeyPairK1K2KBEK()
                                                                           .getValue0());
        assertEquals(Bytes.allocate(0), kb.getKeyPairK1K2KBEK()
                                          .getValue1());
        assertEquals(Bytes.parseHex("31FE334A0E1120D78C1C970D99E77530"), kb.getKeyPairK1K2KBMK()
                                                                           .getValue0());
        assertEquals(Bytes.allocate(0), kb.getKeyPairK1K2KBMK()
                                          .getValue1());
        // The above pass implying we can get the Clear key using the KBEK.
        // The following WILL FAIL. Implying the MAC key generated is not correct or the
        // data used for MACing is not correct.
        // Currently don't have a Thales spec that tells me what is the correct way for
        // generating the MAC key and MACing data
        assertEquals(Bytes.parseHex("459DED8BE95188D9"), kb.getMessageMAC());

    }

    @Test
    @DisplayName("Thales Validate AES256 KBPK keyblock type 1: test will fail for MAC mismatch")
    void decryptAndValidateAES256KBPKeyBlockType1() throws Exception {
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
        System.out.println(kb.toString());
        assertEquals(Bytes.parseHex("CF29A901B5B5DA7028693D4BE058A7B366D3CD2F5862D94E97BCD6D9F28B414A"),
                kb.getEncryptedKey());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F23D4C749F32D15DF992467829C1E"),
                kb.getLengthEncodedPaddedClearKey());
        assertEquals(Bytes.parseHex("23D4C749F32D15DF992467829C1E"), kb.getClearKeyPadding());
        assertEquals(Bytes.parseHex("0080F039121BEC83D26B169BDCD5B22AAF8F"), kb.getlengthEncodedClearKey());
        assertEquals(Bytes.parseHex("1B39BAA881FCEDC1CD5138CC5A31F2E8"), kb.getKeyPairK1K2KBEK()
                                                                           .getValue0());
        assertEquals(Bytes.parseHex("2E1BB7EA3B29CF875F6AAB21268F0D17"), kb.getKeyPairK1K2KBEK()
                                                                           .getValue1());

        assertEquals(Bytes.parseHex("B9C8CD6543528A1C6859765503FBB3A8"), kb.getKeyPairK1K2KBMK()
                                                                           .getValue0());
        assertEquals(Bytes.parseHex("7C533BC73933513AF534A90F525308F2"), kb.getKeyPairK1K2KBMK()
                                          .getValue1());
        // The above pass implying we can get the Clear key using the KBEK.
        // The following WILL FAIL. Implying the MAC key generated is not correct or the
        // data used for MACing is not correct.
        // Currently don't have a Thales spec that tells me what is the correct way for
        // generating the MAC key and MACing data
        assertEquals(Bytes.parseHex("459DED8BE95188D9"), kb.getMessageMAC());

    }

}
