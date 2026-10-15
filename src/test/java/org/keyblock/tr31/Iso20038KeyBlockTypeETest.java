package org.keyblock.tr31;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import at.favre.lib.bytes.Bytes;

/**
 * Key block format version E, ISO 20038:2017. It derives keys the same way type D does except that
 * the encryption key derivation input carries key usage 0x0002, and the confidential data is
 * enciphered with AES-CTR instead of AES-CBC.
 */
class Iso20038KeyBlockTypeETest {

    /** The KBPK really is the ASCII text "256-bit AES wrapping (ISO 20038)". */
    private static final String KBPK = "3235362D62697420414553207772617070696E67202849534F20323030333829";

    /** ISO 20038:2017, B.2 */
    private static final String BLOCK = "E0084B0TV16N0000B2AE5E26BBA7F246E84D5EA24167E208A6B66EF2E27E55A5"
            + "2DB52F0AEACB94C57547";

    /** The ASCII text "wrapped 3DES key" */
    private static final String CLEAR_KEY = "777261707065642033444553206B6579";

    @Test
    @DisplayName("Version E unwraps the published ISO 20038 example")
    void unwrapIso20038Example() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK, KBPK);

        assertEquals("E0084B0TV16N0000", kb.getHeader()
                                           .toString());
        assertEquals(Bytes.parseHex(CLEAR_KEY), kb.getClearKey());
        assertEquals(Bytes.parseHex("6EF2E27E55A52DB52F0AEACB94C57547"), kb.getMessageMAC());
    }

    @Test
    @DisplayName("Version E confidential data is not padded to a block multiple")
    void payloadIsNotBlockPadded() throws Exception {
        // A 16 byte key gives an 18 byte payload, which is not a multiple of the 16 byte block
        // size. A stream cipher preserves the length, so the block stays 84 characters long.
        assertEquals(16, Bytes.parseHex(CLEAR_KEY).length());
        assertEquals(84, BLOCK.length());

        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK, KBPK);

        assertEquals(18, kb.getLengthEncodedPaddedClearKey()
                           .length());
        // no padding bytes are added for a stream cipher, the payload is exactly length + key
        assertEquals(0, kb.getClearKeyPadding() == null ? 0 : kb.getClearKeyPadding()
                                                                     .length());
        assertEquals(BLOCK.length(), kb.getHeader()
                                          .getKeyBlockLength());
    }

    @Test
    @DisplayName("Version E regenerates the published example byte for byte")
    void regenerateIso20038Example() throws Exception {
        Header header = new Header(KeyblockType._E_ISO20038_AES_KEY_DERIVATION, KeyUsage._B0_BDK_BASE_DERIVATION_KEY,
                Export.N_NON_EXPORTABLE, Algorithm._T_TRIPLE_DES, KeyUseFor.V_MAC_VERIFY_ONLY, "16");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex(CLEAR_KEY));
        kb.setKBPK(KBPK);
        kb.generate();

        assertEquals(BLOCK, kb.toString());
    }

    @Test
    @DisplayName("Version E round trips for every AES KBPK length")
    void roundTripEveryKbpkLength() throws Exception {
        String[] kbpks = { "000102030405060708090A0B0C0D0E0F",// AES 128
                "000102030405060708090A0B0C0D0E0F1011121314151617",// AES 192
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" };// AES 256

        for (String kbpk : kbpks) {
            Header header = new Header(KeyblockType._E_ISO20038_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                    Export.N_NON_EXPORTABLE, Algorithm._A_AES, KeyUseFor.E_ENCRYPT_ONLY, "00");

            TR31KeyBlock kb = new TR31KeyBlock(header);
            kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));
            kb.setKBPK(kbpk);
            kb.generate();

            String keyBlock = kb.toString();
            assertEquals(keyBlock.length(), Integer.parseInt(keyBlock.substring(1, 5)), kbpk);

            TR31KeyBlock decrypted = new TR31KeyBlock();
            decrypted.decryptKeyBlock(keyBlock, kbpk);
            assertEquals(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"), decrypted.getClearKey(), kbpk);
        }
    }

    @Test
    @DisplayName("Version E does not produce the same block as version D")
    void isNotInterchangeableWithTypeD() throws Exception {
        String kbpk = "000102030405060708090A0B0C0D0E0F";

        Header e = new Header(KeyblockType._E_ISO20038_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                Export.N_NON_EXPORTABLE, Algorithm._A_AES, KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock typeE = new TR31KeyBlock(e);
        typeE.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));
        typeE.setKBPK(kbpk);
        typeE.generate();

        Header d = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                Export.N_NON_EXPORTABLE, Algorithm._A_AES, KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock typeD = new TR31KeyBlock(d);
        typeD.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8"));
        typeD.setKBPK(kbpk);
        typeD.generate();

        org.junit.jupiter.api.Assertions.assertNotEquals(typeD.getMessageMAC(), typeE.getMessageMAC());
        org.junit.jupiter.api.Assertions.assertNotEquals(typeD.getEncryptedKey(), typeE.getEncryptedKey());
        // type D pads the payload to a block multiple, type E does not
        assertEquals(32, typeD.getEncryptedKey()
                             .length());
        assertEquals(18, typeE.getEncryptedKey()
                             .length());
    }

    /**
     * A tampered key block must be rejected with one of the two exceptions this API documents.
     * {@code assertThrows(Exception.class, ...)} would also pass for a {@code NullPointerException}
     * or a {@code StringIndexOutOfBoundsException}, so it cannot tell a clean rejection from a
     * crash, which is the distinction this test exists to make.
     */
    private static void assertRejectedCleanly(String keyBlock, String kbpk, String where) {
        Throwable thrown = assertThrows(Throwable.class, () -> new TR31KeyBlock()
                .decryptKeyBlock(keyBlock, kbpk), where);

        assertTrue(thrown instanceof SecurityException || thrown instanceof IllegalArgumentException,
                where + " was rejected with " + thrown.getClass().getName() + " rather than a "
                        + "SecurityException or IllegalArgumentException: " + thrown.getMessage());
    }

    @Test
    @DisplayName("Version E rejects the wrong KBPK and tampering")
    void rejectsBadInput() throws Exception {
        assertThrows(SecurityException.class, () -> new TR31KeyBlock()
                                                       .decryptKeyBlock(BLOCK,
                                                               "000102030405060708090A0B0C0D0E0F"));

        for (int i = 16; i < BLOCK.length(); i++) {
            StringBuilder tampered = new StringBuilder(BLOCK);
            char c = tampered.charAt(i);
            tampered.setCharAt(i, c == 'A' ? 'B' : 'A');
            if (tampered.toString()
                       .equals(BLOCK)) {
                continue;
            }
            assertRejectedCleanly(tampered.toString(), KBPK, "a change at position " + i);
        }
    }
}