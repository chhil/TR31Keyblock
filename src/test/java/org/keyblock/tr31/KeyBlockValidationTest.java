package org.keyblock.tr31;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import at.favre.lib.bytes.Bytes;

/**
 * Header and optional block validation. The checks that are always applied must not reject any
 * key block that a real implementation produces, so the published examples are all still
 * accepted.
 */
class KeyBlockValidationTest {

    private static final String KBPK_AES_256 = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6";
    private static final String CLEAR_KEY_16 = "3F419E1CB7079442AA37474C2EFBF8B8";

    /** Header of the example in ANSI X9.143:2021 8.2, its KS data is not hexadecimal. */
    private static final String X9143_82_HEADER = "D0192C0AVA1N0300KS08VM9ATS1A2018-06-18T20:42:39.22PB0E0000000000";

    private static void parse(String header) {
        new Header(header);
    }

    @Test
    @DisplayName("Every published example still parses")
    void publishedExamplesStillParse() {
        assertDoesNotThrow(() -> parse("A0072P0TE00E0000"));
        assertDoesNotThrow(() -> parse("B0080P0TE00E0000"));
        assertDoesNotThrow(() -> parse("C0096B0TX12S0100KS1800604B120F9292800000"));
        assertDoesNotThrow(() -> parse("D0112P0AE00E0000"));
        assertDoesNotThrow(() -> parse("E0084B0TV16N0000"));
        assertDoesNotThrow(() -> parse("00072P0TE00E0000"));
        // ANSI X9.143:2021 8.2, whose KS optional block data is not hexadecimal
        assertDoesNotThrow(() -> parse("D0192C0AVA1N0300KS08VM9ATS1A2018-06-18T20:42:39.22PB0E0000000000"));
    }

    @Test
    @DisplayName("Malformed header fields are rejected")
    void malformedHeaderFieldsAreRejected() {
        // Key block length must be numeric
        assertThrows(IllegalArgumentException.class, () -> parse("A00X2P0TE00E0000"));
        // Number of optional blocks must be numeric
        assertThrows(IllegalArgumentException.class, () -> parse("D0112P0AE00EX000"));
        // Key usage must be alphanumeric
        assertThrows(IllegalArgumentException.class, () -> parse("D0112P-TE00E000"));
        // A truncated header is rejected rather than throwing StringIndexOutOfBounds
        assertThrows(IllegalArgumentException.class, () -> parse("D0112P0A"));
    }

    @Test
    @DisplayName("The reserved field must be zero")
    void reservedFieldMustBeZero() {
        // 16 characters, so this is rejected by the reserved field check and not by the length
        // check that a shorter string would trip
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parse("D0112P0AE00E00FF"));
        assertTrue(e.getMessage()
                       .contains("Reserved header field must be '00'"), e.getMessage());

        assertDoesNotThrow(() -> parse("D0112P0AE00E0000"));
    }

    @Test
    @DisplayName("A header truncated inside its optional blocks is rejected as a malformed header")
    void truncatedOptionalBlocksAreRejectedCleanly() {
        // Declares one optional block but the string ends at the fixed 16 character header
        IllegalArgumentException missingId = assertThrows(IllegalArgumentException.class,
                () -> parse("B0080P0TE00E0100"));
        assertTrue(missingId.getMessage()
                           .contains("optional block ID"), missingId.getMessage());

        // Declares an optional block but stops before its length field
        assertThrows(IllegalArgumentException.class, () -> parse("B0080P0TE00E0100KS"));

        // Extended form declaring a length of length of 0xFF with only a few characters left
        IllegalArgumentException truncatedExtended = assertThrows(IllegalArgumentException.class,
                () -> parse("B0080P0TE00E0100KS00FF" + "0".repeat(50)));
        assertTrue(truncatedExtended.getMessage()
                                   .contains("optional block 'KS' extended length"), truncatedExtended.getMessage());

        // Every one of these is an IllegalArgumentException, not a StringIndexOutOfBoundsException,
        // so a caller catching IllegalArgumentException around a parse catches all of them
    }

    @Test
    @DisplayName("An extended length that cannot be a number is rejected as a malformed header")
    void nonNumericExtendedLengthIsRejectedCleanly() {
        // A length of length wide enough that the length cannot fit in an int
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> parse("B0080P0TE00E0100KS000C" + "F".repeat(12) + "ZZ"));
        assertTrue(e.getMessage()
                       .contains("not a hexadecimal number"), e.getMessage());
    }

    @Test
    @DisplayName("Unknown field values produce a clear error rather than NoSuchElementException")
    void unknownValuesAreRejectedClearly() {
        IllegalArgumentException type = assertThrows(IllegalArgumentException.class,
                () -> parse("Z0080P0TE00E0000"));
        assertTrue(type.getMessage()
                       .contains("key block version ID"), type.getMessage());

        assertThrows(IllegalArgumentException.class, () -> parse("B0080ZZTE00E0000"));
        assertThrows(IllegalArgumentException.class, () -> parse("B0080P0ZE00E000"));
        assertThrows(IllegalArgumentException.class, () -> parse("B0080P0TZ00E000"));
        assertThrows(IllegalArgumentException.class, () -> parse("B0080P0TZE00000"));
    }

    @Test
    @DisplayName("A repeated optional block ID is rejected")
    void duplicateOptionalBlockIdsAreRejected() {
        // Two KS optional blocks, which A.5.6 does not allow
        assertThrows(IllegalArgumentException.class,
                () -> parse("B0080P0TE00E0200KS0400AB000000KS04AABBCCDD"));
    }

    @Test
    @DisplayName("An optional block declaring an impossible length is rejected")
    void impossibleOptionalBlockLengthIsRejected() {
        // KS block claims 0xFF bytes of data but none follow
        assertThrows(IllegalArgumentException.class,
                () -> parse("B0080P0TE00E0100KSFF00112233"));
    }

    @Test
    @DisplayName("Optional block data is only format checked when strict validation is on")
    void optionalBlockDataValidationIsOptIn() {
        // The KS data 'VM9A' in the example published in X9.143:2021 8.2 is not hexadecimal
        assertDoesNotThrow(() -> parse(X9143_82_HEADER));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new Header(X9143_82_HEADER, true));
        assertTrue(e.getMessage()
                       .contains("'KS'"), e.getMessage());

        // A conforming KS block still passes with strict validation on
        assertDoesNotThrow(() -> parse("C0096B0TX12S0100KS1800604B120F9292800000"));
    }

    @Test
    @DisplayName("Key length must match the algorithm of the header")
    void keyLengthMustMatchAlgorithm() {
        // 20 bytes is not a valid AES or TDEA key length
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> {
            Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                    Export.N_NON_EXPORTABLE, Algorithm._A_AES, KeyUseFor.E_ENCRYPT_ONLY, "00");
            TR31KeyBlock kb = new TR31KeyBlock(header);
            kb.setClearKey(Bytes.parseHex("3F419E1CB7079442AA37474C2EFBF8B8011223344"));
            kb.setKBPK(KBPK_AES_256);
            kb.generate();
        });
        assertTrue(e.getMessage()
                       .contains("16, 24 or 32 bytes"), e.getMessage());
    }

    @Test
    @DisplayName("Every valid symmetric key length is still accepted")
    void validKeyLengthsAreAccepted() throws Exception {
        record Case(Algorithm algorithm, String kbpk, String key) { }
        Case[] cases = { new Case(Algorithm._A_AES, KBPK_AES_256, CLEAR_KEY_16),
                new Case(Algorithm._A_AES, KBPK_AES_256, CLEAR_KEY_16 + "0102030405060708"),
                new Case(Algorithm._A_AES, KBPK_AES_256, CLEAR_KEY_16 + "0102030405060708090A0B0C0D0E0F10"),
                new Case(Algorithm._T_TRIPLE_DES, "DD7515F2BFC17F85CE48F3CA25CB21F6", CLEAR_KEY_16),
                new Case(Algorithm._T_TRIPLE_DES, "DD7515F2BFC17F85CE48F3CA25CB21F6",
                        CLEAR_KEY_16 + "0102030405060708") };

        for (Case c : cases) {
            Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                    Export.N_NON_EXPORTABLE, c.algorithm(), KeyUseFor.E_ENCRYPT_ONLY, "00");
            TR31KeyBlock kb = new TR31KeyBlock(header);
            kb.setClearKey(Bytes.parseHex(c.key()));
            kb.setKBPK(c.kbpk());
            kb.generate();

            TR31KeyBlock decrypted = new TR31KeyBlock();
            decrypted.decryptKeyBlock(kb.toString(), c.kbpk());
            assertTrue(c.key()
                          .equalsIgnoreCase(decrypted.getClearKey()
                                                        .encodeHex()),
                    "round trip failed for " + c.algorithm() + " with " + (c.key().length() / 2) + " byte key");
        }
    }
}