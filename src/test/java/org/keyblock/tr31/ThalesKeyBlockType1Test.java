package org.keyblock.tr31;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import at.favre.lib.bytes.Bytes;

/**
 * Thales key block type 1 is a proprietary format, it is not covered by ASC X9 TR 31. Keys are
 * derived exactly as they are for type D, but the block is protected encrypt-then-MAC with a
 * truncated AES CMAC over the header and the encrypted key.
 */
class ThalesKeyBlockType1Test {

    private static final String KBPK_AES_128 = "FED02F85DF1989F76E4F15BC370764CE";
    private static final String KBPK_AES_256 = "9B71333A13F9FAE72F9D0E2DAB4AD6784718012F9244033F3F26A2DE0C8AA11A";

    // 16 header + 64 encrypted + 16 MAC
    private static final String BLOCK_AES_128 = "10096P0TE00E0000"
            + "01309DFC752C7DBE53A3480510652D7B845AF4E211F72B502D9B32AF702A64EA"
            + "459DED8BE95188D9";

    private static final String BLOCK_AES_256 = "10096P0TE00E0000"
            + "CF29A901B5B5DA7028693D4BE058A7B366D3CD2F5862D94E97BCD6D9F28B414A"
            + "377052CE7A04D821";

    private static final String CLEAR_KEY = "F039121BEC83D26B169BDCD5B22AAF8F";

    @Test
    @DisplayName("Thales type 1 with an AES 128 KBPK unwraps and authenticates")
    void unwrapAes128() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_AES_128, KBPK_AES_128);

        assertEquals("10096P0TE00E0000", kb.getHeader()
                                           .toString());
        assertEquals(Bytes.parseHex(CLEAR_KEY), kb.getClearKey());
        assertEquals(Bytes.parseHex("D102DC4312C4649AA966B0D10B56"), kb.getClearKeyPadding());
        assertEquals(Bytes.parseHex("459DED8BE95188D9"), kb.getMessageMAC());
    }

    @Test
    @DisplayName("Thales type 1 with an AES 256 KBPK unwraps and authenticates")
    void unwrapAes256() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_AES_256, KBPK_AES_256);

        assertEquals("10096P0TE00E0000", kb.getHeader()
                                           .toString());
        assertEquals(Bytes.parseHex(CLEAR_KEY), kb.getClearKey());
        assertEquals(Bytes.parseHex("23D4C749F32D15DF992467829C1E"), kb.getClearKeyPadding());
        assertEquals(Bytes.parseHex("377052CE7A04D821"), kb.getMessageMAC());
    }

    @Test
    @DisplayName("Thales type 1 keys are derived exactly as key block type D")
    void keysAreDerivedAsTypeD() throws Exception {
        // The disabled tests in this project asserted these KBEK values and the clear key they
        // produce, they only ever failed on the MAC.
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_AES_128, KBPK_AES_128);

        assertEquals(Bytes.parseHex("A3E44F5D04E47518F20D596FC433AC2B"), kb.getKeyPairK1K2KBEK()
                                                                                     .getValue0());
        assertEquals(Bytes.allocate(0), kb.getKeyPairK1K2KBEK()
                                          .getValue1());
        assertEquals(Bytes.parseHex("31FE334A0E1120D78C1C970D99E77530"), kb.getKeyPairK1K2KBMK()
                                                                                     .getValue0());
    }

    @Test
    @DisplayName("Thales type 1 round trips")
    void roundTrip() throws Exception {
        Header header = new Header(KeyblockType._1_THALES_AES, KeyUsage._P0_PIN_ENCRYPTION,
                Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES, KeyUseFor.E_ENCRYPT_ONLY,
                "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex(CLEAR_KEY));
        kb.setKBPK(KBPK_AES_128);
        kb.generate();

        String keyBlock = kb.toString();

        // 16 header + 64 encrypted + 16 MAC
        assertEquals(96, keyBlock.length());
        assertEquals("10096P0TE00E0000", keyBlock.substring(0, 16));
        assertEquals(96, Integer.parseInt(keyBlock.substring(1, 5)));
        assertEquals(0, keyBlock.length() % 16);

        // Padding is random per the spec, so the ciphertext will not be reproducible, but the
        // block has to authenticate against itself.
        TR31KeyBlock decrypted = new TR31KeyBlock();
        decrypted.decryptKeyBlock(keyBlock, KBPK_AES_128);
        assertEquals(Bytes.parseHex(CLEAR_KEY), decrypted.getClearKey());
    }

    @Test
    @DisplayName("Thales type 1 uses a different MAC to type D")
    void macIsNotTheTypeDmac() throws Exception {
        Header header = new Header(KeyblockType._1_THALES_AES, KeyUsage._P0_PIN_ENCRYPTION,
                Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES, KeyUseFor.E_ENCRYPT_ONLY,
                "00");

        TR31KeyBlock thales = new TR31KeyBlock(header);
        thales.setClearKey(Bytes.parseHex(CLEAR_KEY));
        thales.setKBPK(KBPK_AES_128);
        thales.generate();

        // The same KBPK and clear key wrapped as a type D block must not produce the same MAC,
        // otherwise the two formats would be indistinguishable.
        Header dHeader = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES, KeyUseFor.E_ENCRYPT_ONLY,
                "00");
        TR31KeyBlock typeD = new TR31KeyBlock(dHeader);
        typeD.setClearKey(Bytes.parseHex(CLEAR_KEY));
        typeD.setKBPK(KBPK_AES_128);
        typeD.generate();

        assertNotEquals(typeD.getMessageMAC(), thales.getMessageMAC());
        assertEquals(8, thales.getMessageMAC()
                               .length());
        assertEquals(16, typeD.getMessageMAC()
                               .length());
    }

    @Test
    @DisplayName("Thales type 1 rejects the wrong KBPK and tampering")
    void rejectsBadInput() throws Exception {
        assertThrows(SecurityException.class, () -> new TR31KeyBlock()
                                                       .decryptKeyBlock(BLOCK_AES_128, KBPK_AES_256));

        for (int i = 16; i < BLOCK_AES_128.length(); i++) {
            StringBuilder tampered = new StringBuilder(BLOCK_AES_128);
            char c = tampered.charAt(i);
            tampered.setCharAt(i, c == 'A' ? 'B' : 'A');
            if (tampered.toString()
                       .equals(BLOCK_AES_128)) {
                continue;
            }

            assertThrows(Exception.class, () -> new TR31KeyBlock()
                                                     .decryptKeyBlock(tampered.toString(), KBPK_AES_128),
                    "a change at position " + i + " was accepted");
        }
    }
}