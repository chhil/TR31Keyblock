package org.keyblock.tr31;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import at.favre.lib.bytes.Bytes;

/**
 * ASC X9 TR 31-2018 A.5.6 requires the combined length of all Optional Blocks to be a multiple of
 * the encryption block size, which in turn makes the whole header a multiple of it because the
 * fixed 16 character portion of the header already is.
 */
class OptionalBlockPaddingTest {

    private static final String CLEAR_KEY_16 = "3F419E1CB7079442AA37474C2EFBF8B8";
    private static final String KBPK_AES_256 = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6";

    private static Header header(KeyblockType type) {
        return new Header(type, KeyUsage._P0_PIN_ENCRYPTION, Export.N_NON_EXPORTABLE,
                type.isAES() ? Algorithm._A_AES : Algorithm._T_TRIPLE_DES, KeyUseFor.E_ENCRYPT_ONLY, "00");
    }

    private static String repeat(char c, int n) {
        return String.valueOf(c).repeat(n);
    }

    @Test
    @DisplayName("Padding block aligns the header with the TDEA and AES block sizes")
    void headerIsAlwaysBlockAligned() throws Exception {
        List<KeyblockType> types = List.of(KeyblockType._C_TDEA_KEY_VARIANT_BINDING,
                                          KeyblockType._D_AES_KEY_DERIVATION);

        for (KeyblockType type : types) {
            int cipherBlockSize = type.getCipherBlockSize();

            for (int dataLength = 0; dataLength <= 40; dataLength++) {
                Header header = header(type);
                header.addOptionalBlocksAndPad(new OptionalBlock(DefinedOptionalBlockType._IK,
                        repeat('0', dataLength)));

                String headerString = header.toString();
                assertEquals(0, headerString.length() % cipherBlockSize,
                        "type " + type + " optional block data length " + dataLength + " produced header "
                                + headerString);
            }
        }
    }

    @Test
    @DisplayName("Padded header still parses and preserves every optional block")
    void paddedHeaderRoundTripsThroughTheParser() throws Exception {
        for (KeyblockType type : List.of(KeyblockType._C_TDEA_KEY_VARIANT_BINDING,
                                         KeyblockType._D_AES_KEY_DERIVATION)) {
            for (int dataLength = 0; dataLength <= 24; dataLength++) {
                Header header = header(type);
                header.addOptionalBlocksAndPad(new OptionalBlock(DefinedOptionalBlockType._IK,
                        repeat('A', dataLength)));

                Header parsed = new Header(header.toString());
                assertEquals(header.toString(), parsed.toString(), "type " + type + ", data length "
                        + dataLength);
            }
        }
    }

    @Test
    @DisplayName("No padding block is appended when the optional blocks are already aligned")
    void noPaddingBlockWhenAlreadyAligned() throws Exception {
        // 20 characters of data makes the optional block 24 characters long, already a multiple of
        // the 8 character TDEA block size.
        Header header = header(KeyblockType._C_TDEA_KEY_VARIANT_BINDING);
        header.addOptionalBlocksAndPad(
                new OptionalBlock(DefinedOptionalBlockType._KS, "00604B120F9292800000"));

        assertEquals(1, Integer.parseInt(header.toString()
                                               .substring(12,
                                                       14)), "expected a single optional block, header was "
                                               + header);
    }

    @Test
    @DisplayName("Multiple optional blocks plus padding are aligned")
    void multipleOptionalBlocksAreAligned() throws Exception {
        Header header = header(KeyblockType._D_AES_KEY_DERIVATION);
        header.addOptionalBlocksAndPad(new OptionalBlock(DefinedOptionalBlockType._KS, "0A1412345678"),
                                      new OptionalBlock(DefinedOptionalBlockType._TS, "2018-06-18T20:42:39.22"),
                                      new OptionalBlock(DefinedOptionalBlockType._KP, "ABCD"));

        String headerString = header.toString();
        assertEquals(0, headerString.length() % 16, headerString);
        assertEquals(headerString, new Header(headerString)
                                         .toString());
    }

    @Test
    @DisplayName("Generated key block with optional blocks has a block size multiple length")
    void generatedKeyBlockIsBlockAligned() throws Exception {
        Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                Export.N_NON_EXPORTABLE, Algorithm._A_AES, KeyUseFor.E_ENCRYPT_ONLY, "00");
        header.addOptionalBlocksAndPad(new OptionalBlock(DefinedOptionalBlockType._IK, "0E1111111122222"));

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex(CLEAR_KEY_16));
        kb.setClearKeyPadding(Bytes.parseHex("1C2965473CE206BB855B01533782"));
        kb.setKBPK(KBPK_AES_256);
        kb.generate();

        String keyBlock = kb.toString();

        // A conforming receiver validates that the total length is a multiple of the encryption
        // block size before it will look at anything else, see X9.143 5.3.2.4 step 1.
        assertEquals(0, keyBlock.length() % 16, "key block length must be a multiple of 16: " + keyBlock);
        assertEquals(keyBlock.length(), Integer.parseInt(keyBlock.substring(1, 5)),
                "declared key block length must match the actual length: " + keyBlock);

        TR31KeyBlock decrypted = new TR31KeyBlock();
        decrypted.decryptKeyBlock(keyBlock, KBPK_AES_256);
        assertEquals(Bytes.parseHex(CLEAR_KEY_16), decrypted.getClearKey());
    }

    @Test
    @DisplayName("ANSI X9 TR 31-2018 A.7.3.1 example reproduced exactly")
    void specExample2aWithOptionalBlock() throws Exception {
        // See example in ANSI X9 TR-31-2018 A.7.3.1, the key set identifier optional block is
        // already 8 byte aligned so no padding block is expected.
        Header header = new Header(KeyblockType._C_TDEA_KEY_VARIANT_BINDING,
                KeyUsage._B0_BDK_BASE_DERIVATION_KEY, Export.S_SENSITIVE_EXPORTABLE_UNDER_UNTRUSTED_KEY,
                Algorithm._T_TRIPLE_DES, KeyUseFor.X_DERIVE_OTHER_KEYS, "12");
        header.addOptionalBlocksAndPad(
                new OptionalBlock(DefinedOptionalBlockType._KS, "00604B120F9292800000"));

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex("EDB380DD340BC2620247D445F5B8D678"));
        kb.setClearKeyPadding(Bytes.parseHex("8546A8ED98D1"));
        kb.setKBPK("B8ED59E0A279A295E9F5ED7944FD06B9");
        kb.generate();

        assertEquals("C0096B0TX12S0100KS1800604B120F9292800000"
                + "BFB9B689CB567E66FC3FEE5AD5F52161FC6545B9D6098901"
                + "5D02155C", kb.toString());
    }

    @Test
    @DisplayName("Optional block padding never shrinks an already generated key block")
    void keyBlockLengthIsConsistentAfterPadding() throws Exception {
        Header header = header(KeyblockType._D_AES_KEY_DERIVATION);
        header.addOptionalBlocksAndPad(new OptionalBlock(DefinedOptionalBlockType._IK, "0E1111111122222"));

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex(CLEAR_KEY_16));
        kb.setKBPK(KBPK_AES_256);
        kb.generate();

        String keyBlock = kb.toString();
        assertTrue(keyBlock.length() % 16 == 0, keyBlock);
        assertEquals(keyBlock.length(), Integer.parseInt(keyBlock.substring(1, 5)), keyBlock);
    }
}