package org.keyblock.tr31;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import at.favre.lib.bytes.Bytes;

/**
 * The length prefix of the confidential data comes out of a decryption that has not been
 * authenticated yet, so it has to be validated rather than used as a slice offset.
 */
class KeyBlockUnwrapTest {

    private static final String CLEAR_KEY_16 = "3F419E1CB7079442AA37474C2EFBF8B8";
    private static final String CLEAR_KEY_24 = "3F419E1CB7079442AA37474C2EFBF8B31122334455667788";
    private static final String KBPK_TDEA_2 = "DD7515F2BFC17F85CE48F3CA25CB21F6";
    private static final String KBPK_TDEA_3 = "260892192061C8760BDF235E1619B057B334FED0EFA74F32";
    private static final String KBPK_AES_256 = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6";
    private static final String KBPK_AES_128 = "FED02F85DF1989F76E4F15BC370764CE";
    private static final String KBPK_AES_192 = "6BF89E64F80DBC70E9D6AEB03454E6544A67F725436E3BD3";

    private static String generate(KeyblockType type, String kbpk, String clearKey) throws Exception {
        Header header = new Header(type, KeyUsage._P0_PIN_ENCRYPTION, Export.E_EXPORTABLE_UNDER_TRUSTED_KEY,
                Algorithm._T_TRIPLE_DES, KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex(clearKey));
        kb.setKBPK(kbpk);
        kb.generate();
        return kb.toString();
    }

    @Test
    @DisplayName("Unwrapping with the wrong KBPK fails cleanly rather than crashing")
    void wrongKbpkIsRejectedCleanly() throws Exception {
        String keyBlock = generate(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KBPK_TDEA_2, CLEAR_KEY_16);

        SecurityException e = assertThrows(SecurityException.class,
                () -> new TR31KeyBlock()
                        .decryptKeyBlock(keyBlock, KBPK_TDEA_3));
        assertTrue(e.getMessage()
                    .startsWith("Invalid key length") || e.getMessage()
                                                                 .startsWith("Key length")
                            || e.getMessage()
                                   .startsWith("Confidential data"),
                "expected a validation failure but got: " + e.getMessage());
    }

    @Test
    @DisplayName("Unwrapping an AES key block with the wrong KBPK fails cleanly")
    void wrongKbpkIsRejectedCleanlyForAes() throws Exception {
        String keyBlock = generate(KeyblockType._D_AES_KEY_DERIVATION, KBPK_AES_256, CLEAR_KEY_16);

        assertThrows(SecurityException.class, () -> new TR31KeyBlock()
                                                       .decryptKeyBlock(keyBlock,
                                                               "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE7"));
    }

    /**
     * A tampered key block must be rejected with one of the two exceptions this API documents,
     * not with an arbitrary {@code RuntimeException}. Asserting {@code Exception.class} would also
     * pass for a {@code NullPointerException} or a {@code StringIndexOutOfBoundsException}, which
     * is precisely the crash the validation was added to remove.
     */
    private static void assertRejectedCleanly(String keyBlock, String kbpk, String where) {
        Throwable thrown = assertThrows(Throwable.class, () -> new TR31KeyBlock()
                .decryptKeyBlock(keyBlock, kbpk), where);

        assertTrue(thrown instanceof SecurityException || thrown instanceof IllegalArgumentException,
                where + " was rejected with " + thrown.getClass().getName() + " rather than a "
                        + "SecurityException or IllegalArgumentException: " + thrown.getMessage());
    }

    @Test
    @DisplayName("Every single character change in a key block is rejected")
    void tamperingIsRejected() throws Exception {
        String keyBlock = generate(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KBPK_TDEA_2, CLEAR_KEY_16);

        // Skip the header, every character after it is part of the ciphertext or the MAC.
        for (int i = 16; i < keyBlock.length(); i++) {
            StringBuilder tampered = new StringBuilder(keyBlock);
            char c = tampered.charAt(i);
            tampered.setCharAt(i, c == 'A' ? 'B' : 'A');
            if (keyBlock.equals(tampered.toString())) {
                continue;
            }

            assertRejectedCleanly(tampered.toString(), KBPK_TDEA_2, "a change at position " + i);
        }
    }

    @Test
    @DisplayName("A header declaring a length that does not match is rejected")
    void declaredLengthMustMatch() throws Exception {
        String keyBlock = generate(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KBPK_TDEA_2, CLEAR_KEY_16);

        // Inflate the declared key block length
        StringBuilder bad = new StringBuilder(keyBlock);
        bad.replace(1, 5, "0099");

        assertThrows(IllegalArgumentException.class, () -> new TR31KeyBlock()
                                                                 .decryptKeyBlock(bad.toString(), KBPK_TDEA_2));
    }

    @Test
    @DisplayName("Key block types report the MAC length the format actually uses")
    void macLengthsMatchTheFormats() {
        // 5.3.3.2: variant binding blocks carry a 32 bit MAC to blunt attacks on the CBC MAC
        assertEquals(4, KeyblockType._A_KEY_VARIANT_BINDING.getMACLen());
        assertEquals(4, KeyblockType._C_TDEA_KEY_VARIANT_BINDING.getMACLen());
        assertEquals(4, KeyblockType._0_THALES_DES.getMACLen());
        // 5.3.2.1: TDEA derivation uses an 8 byte CMAC, AES derivation a 16 byte CMAC
        assertEquals(8, KeyblockType._B_TDEA_KEY_DERIVATION_BINDING.getMACLen());
        assertEquals(16, KeyblockType._D_AES_KEY_DERIVATION.getMACLen());
        // Thales type 1 is AES wrapped but truncated to a 64 bit MAC, not a 128 bit CMAC
        assertEquals(8, KeyblockType._1_THALES_AES.getMACLen());
    }

    @Test
    @DisplayName("Thales type 1 declares its real MAC length so the header length adds up")
    void thalesTypeOneLengthIsSelfConsistent() throws Exception {
        // From the Thales example in the test sources: 16 header + 64 ciphertext + 16 MAC = 96
        Header header = new Header(KeyblockType._1_THALES_AES, KeyUsage._P0_PIN_ENCRYPTION,
                Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES, KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex(CLEAR_KEY_16));
        kb.setKBPK("FED02F85DF1989F76E4F15BC370764CE");
        kb.generate();

        String keyBlock = kb.toString();
        assertEquals(96, keyBlock.length());
        assertEquals(96, Integer.parseInt(keyBlock.substring(1, 5)));
        assertEquals("10096P0TE00E0000", keyBlock.substring(0, 16));
    }

/**
 * The KBPK algorithm and its legal lengths follow the key block type, see
 * {@link TR31KeyBlock#setKBPK(String)}: TDEA for A, B, C and the Thales 0, AES for D, E and
 * the Thales 1. One table, used by every test below, so a combination that no test happens to
 * touch cannot silently go unexercised and no test can pair a type with an illegal KBPK.
 */
private record KbpkCase(KeyblockType type, String kbpk, int kbpkBytes) { }

private static List<KbpkCase> kbpkMatrix() {
        return List.of(
                new KbpkCase(KeyblockType._A_KEY_VARIANT_BINDING, KBPK_TDEA_2, 16),
                new KbpkCase(KeyblockType._A_KEY_VARIANT_BINDING, KBPK_TDEA_3, 24),
                new KbpkCase(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KBPK_TDEA_2, 16),
                new KbpkCase(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KBPK_TDEA_3, 24),
                new KbpkCase(KeyblockType._C_TDEA_KEY_VARIANT_BINDING, KBPK_TDEA_2, 16),
                new KbpkCase(KeyblockType._C_TDEA_KEY_VARIANT_BINDING, KBPK_TDEA_3, 24),
                new KbpkCase(KeyblockType._D_AES_KEY_DERIVATION, KBPK_AES_128, 16),
                new KbpkCase(KeyblockType._D_AES_KEY_DERIVATION, KBPK_AES_192, 24),
                new KbpkCase(KeyblockType._D_AES_KEY_DERIVATION, KBPK_AES_256, 32),
                new KbpkCase(KeyblockType._E_ISO20038_AES_KEY_DERIVATION, KBPK_AES_128, 16),
                new KbpkCase(KeyblockType._E_ISO20038_AES_KEY_DERIVATION, KBPK_AES_192, 24),
                new KbpkCase(KeyblockType._E_ISO20038_AES_KEY_DERIVATION, KBPK_AES_256, 32),
                new KbpkCase(KeyblockType._0_THALES_DES, KBPK_TDEA_2, 16),
                new KbpkCase(KeyblockType._0_THALES_DES, KBPK_TDEA_3, 24),
                new KbpkCase(KeyblockType._1_THALES_AES, KBPK_AES_128, 16),
                new KbpkCase(KeyblockType._1_THALES_AES, KBPK_AES_192, 24),
                new KbpkCase(KeyblockType._1_THALES_AES, KBPK_AES_256, 32));
}

@Test
    @DisplayName("Every type round trips with every KBPK length that type accepts")
    void everyTypeRoundTripsWithEveryLegalKbpkLength() throws Exception {
        for (KbpkCase c : kbpkMatrix()) {
            String where = c.type() + " with a " + c.kbpkBytes() + " byte KBPK";
            // a 16 byte key is a valid double length TDEA key and a valid AES-128 key
            String keyBlock = generate(c.type(), c.kbpk(), CLEAR_KEY_16);

            TR31KeyBlock decrypted = new TR31KeyBlock();
            decrypted.decryptKeyBlock(keyBlock, c.kbpk());

            assertEquals(Bytes.parseHex(CLEAR_KEY_16), decrypted.getClearKey(), where);
            assertEquals(c.type(), decrypted.getHeader()
                                           .getKeyBlockType(), where);
            assertEquals(keyBlock.length(), Integer.parseInt(keyBlock.substring(1, 5)),
                    where + " declared the wrong length");

            // The MAC is taken over the header, so a header that does not re-serialise to itself
            // would authenticate against different bytes on the way back in
            assertEquals(keyBlock.substring(0, decrypted.getHeader()
                                                         .getLength()),
                    decrypted.getHeader()
                             .toString(), where + " header did not survive a round trip");
        }
    }

    @Test
    @DisplayName("A KBPK of the right length but the wrong value is rejected as a MAC failure")
    void wrongKbpkValueIsRejectedCleanly() throws Exception {
        for (KbpkCase c : kbpkMatrix()) {
            String where = c.type() + " with a " + c.kbpkBytes() + " byte KBPK of the wrong value";
            String keyBlock = generate(c.type(), c.kbpk(), CLEAR_KEY_16);

            // same length, different value, so only the KBPK is wrong
            StringBuilder other = new StringBuilder(c.kbpk());
            other.setCharAt(0, c.kbpk().charAt(0) == '0' ? '1' : '0');

            Throwable thrown = assertThrows(Throwable.class,
                    () -> new TR31KeyBlock()
                            .decryptKeyBlock(keyBlock, other.toString()), where);
            assertTrue(thrown instanceof SecurityException,
                    where + " was rejected with " + thrown.getClass().getName() + ": "
                            + thrown.getMessage() + ", expected a SecurityException");
        }
    }

    @Test
    @DisplayName("A KBPK length the key block type cannot use is rejected with a clear message")
    void illegalKbpkLengthIsRejectedClearly() {
        // The KBPK algorithm is fixed by the type, so a length that algorithm cannot take is a
        // caller error. Left to the JCE it surfaces as a bare "Wrong key size" from whichever
        // Cipher is built first, which says nothing about which key or what was expected.
        record Case(KeyblockType type, String kbpk, String expected) { }

        Case[] cases = { new Case(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KBPK_AES_256,
                                          "A TDEA key block protection key must be 16 or 24 bytes but was 32"),
                new Case(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, "0011223344556677",
                                          "A TDEA key block protection key must be 16 or 24 bytes but was 8"),
                new Case(KeyblockType._A_KEY_VARIANT_BINDING, KBPK_AES_256,
                                          "A TDEA key block protection key must be 16 or 24 bytes but was 32"),
                new Case(KeyblockType._D_AES_KEY_DERIVATION, "0011223344556677",
                                          "An AES key block protection key must be 16, 24 or 32 bytes but was 8"),
                new Case(KeyblockType._D_AES_KEY_DERIVATION, "00112233445566778899AABBCCDDEEFF00112233",
                                          "An AES key block protection key must be 16, 24 or 32 bytes but was 20"),
                new Case(KeyblockType._E_ISO20038_AES_KEY_DERIVATION, "0011223344556677",
                                          "An AES key block protection key must be 16, 24 or 32 bytes but was 8") };

        for (Case c : cases) {
            Header header = new Header(c.type(), KeyUsage._P0_PIN_ENCRYPTION,
                    Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                    KeyUseFor.E_ENCRYPT_ONLY, "00");
            TR31KeyBlock kb = new TR31KeyBlock(header);

            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> kb.setKBPK(c.kbpk()), c.type() + " accepted a " + (c.kbpk().length() / 2)
                            + " byte KBPK");
            assertEquals(c.expected(), e.getMessage());
        }
    }

    @Test
    @DisplayName("Every KBPK length a type accepts is still accepted")
    void legalKbpkLengthsAreAccepted() throws Exception {
        // the mirror of the test above, so tightening setKBPK cannot quietly narrow what works
        for (KbpkCase c : kbpkMatrix()) {
            Header header = new Header(c.type(), KeyUsage._P0_PIN_ENCRYPTION,
                    Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES,
                    KeyUseFor.E_ENCRYPT_ONLY, "00");
            new TR31KeyBlock(header)
                    .setKBPK(c.kbpk());
        }
    }

    @Test
    @DisplayName("A double length and a triple length TDEA KBPK are different keys")
    void tdeaKbpkLengthsAreNotInterchangeable() throws Exception {
        // A 16 byte TDEA KBPK is expanded to K1||K2||K1 before use, so wrapping with it and then
        // unwrapping with the 24 byte form is using a different KBPK, not a shorter spelling of
        // the same one.
        String keyBlock = generate(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KBPK_TDEA_2, CLEAR_KEY_16);

        assertRejectedCleanly(keyBlock, KBPK_TDEA_3, "a 16 byte KBPK must not unwrap with the 24 byte one");
    }

    @Test
    @DisplayName("Every supported key block type round trips")
    void roundTripAllTypes() throws Exception {
        record Case(KeyblockType type, String kbpk, String clearKey) { }
        Case[] cases = { new Case(KeyblockType._A_KEY_VARIANT_BINDING, KBPK_TDEA_2, CLEAR_KEY_16),
                new Case(KeyblockType._C_TDEA_KEY_VARIANT_BINDING, KBPK_TDEA_3, CLEAR_KEY_24),
                new Case(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KBPK_TDEA_2, CLEAR_KEY_24),
                new Case(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KBPK_TDEA_3, CLEAR_KEY_16),
                new Case(KeyblockType._D_AES_KEY_DERIVATION, KBPK_AES_256, CLEAR_KEY_24),
                new Case(KeyblockType._0_THALES_DES, KBPK_TDEA_3, CLEAR_KEY_24) };

        for (Case c : cases) {
            String keyBlock = generate(c.type(), c.kbpk(), c.clearKey());
            TR31KeyBlock decrypted = new TR31KeyBlock();
            decrypted.decryptKeyBlock(keyBlock, c.kbpk());
            assertEquals(Bytes.parseHex(c.clearKey()), decrypted.getClearKey(),
                    "round trip failed for " + c.type());
        }
    }

    @Test
    @DisplayName("MAC is computed over the cleartext payload, not the ciphertext")
    void macCoversTheCleartextPayload() throws Exception {
        // The published AES example from ASC X9 TR 31-2018 A.7.4.2.5. If the MAC were taken over
        // the ciphertext, or the padding differed, this value would not reproduce.
        String keyBlock = "D0112P0AE00E0000"
                + "B82679114F470F540165EDFBF7E250FCEA43F810D215F8D207E2E417C07156A2"
                + "7E8E31DA05F7425509593D03A457DC34";

        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(keyBlock, KBPK_AES_256);

        assertEquals(Bytes.parseHex(CLEAR_KEY_16), kb.getClearKey());
        assertEquals(Bytes.parseHex("1C2965473CE206BB855B01533782"), kb.getClearKeyPadding());
        assertEquals(Bytes.parseHex("7E8E31DA05F7425509593D03A457DC34"), kb.getMessageMAC());
    }

    @Test
    @DisplayName("Regenerating after changing the clear key produces the new key")
    void regeneratingAfterAKeyChangeIsHonoured() throws Exception {
        Header header = new Header(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, KeyUsage._P0_PIN_ENCRYPTION,
                Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES, KeyUseFor.E_ENCRYPT_ONLY,
                "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setKBPK(KBPK_TDEA_2);
        kb.setClearKey(Bytes.parseHex(CLEAR_KEY_16));
        kb.generate();
        String first = kb.toString();

        // Generating again without changing anything has to be a no-op
        kb.generate();
        assertEquals(first, kb.toString(), "generation must be stable when nothing changed");

        // Change the key after a block has already been generated, the cached padding and the
        // declared key block length must not be reused or the block would still describe the
        // first key.
        kb.setClearKey(Bytes.parseHex(CLEAR_KEY_24));
        kb.generate();
        String second = kb.toString();

        assertEquals(CLEAR_KEY_24, keyOf(second, KBPK_TDEA_2).toUpperCase(),
                "the regenerated block must carry the new key");
        assertEquals(second.length(), Integer.parseInt(second.substring(1, 5)),
                "the regenerated block must declare its own length, not the previous one");
    }

    @Test
    @DisplayName("Changing the padding after a block is generated is honoured")
    void regeneratingAfterAPaddingChangeIsHonoured() throws Exception {
        Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, Algorithm._T_TRIPLE_DES, KeyUseFor.E_ENCRYPT_ONLY,
                "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setKBPK(KBPK_AES_256);
        kb.setClearKey(Bytes.parseHex(CLEAR_KEY_16));
        kb.setClearKeyPadding(Bytes.parseHex("1C2965473CE206BB855B01533782"));
        kb.generate();

        assertEquals(Bytes.parseHex("1C2965473CE206BB855B01533782"), kb.getClearKeyPadding());

        kb.setClearKeyPadding(Bytes.parseHex("AABBCCDDEEFF0011223344556677"));
        kb.generate();

        assertEquals(Bytes.parseHex("AABBCCDDEEFF0011223344556677"), kb.getClearKeyPadding());
        assertEquals(CLEAR_KEY_16, keyOf(kb.toString(), KBPK_AES_256).toUpperCase());
    }

    private static String keyOf(String keyBlock, String kbpk) throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(keyBlock, kbpk);
        return kb.getClearKey()
                  .encodeHex();
    }

    @Test
    @DisplayName("Obfuscation padding refuses algorithms it is not defined for")
    void obfuscationPaddingRejectsUnsupportedAlgorithms() {
        for (Algorithm algorithm : new Algorithm[] { Algorithm._D_DEA, Algorithm._E_ELLIPTIC_CURVE,
                Algorithm._R_RSA, Algorithm._S_DSA, Algorithm._H_HMAC }) {
            Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                    Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, algorithm, KeyUseFor.E_ENCRYPT_ONLY, "00");

            TR31KeyBlock kb = new TR31KeyBlock(header);
            kb.setClearKey(Bytes.parseHex(CLEAR_KEY_16));

            IllegalStateException e = assertThrows(IllegalStateException.class,
                    kb::enforceKeyLengthObfuscationPadding);
            assertTrue(e.getMessage()
                        .contains("not defined for algorithm"), e.getMessage());
        }
    }

    @Test
    @DisplayName("Obfuscation padding pads AES and TDEA out to their maximum length")
    void obfuscationPaddingPadsToMaximumLength() {
        record Case(Algorithm algorithm, String key, int expectedPadding) { }
        Case[] cases = { new Case(Algorithm._A_AES, CLEAR_KEY_16, 16), new Case(Algorithm._A_AES, CLEAR_KEY_24, 8),
                new Case(Algorithm._A_AES, "3F419E1CB7079442AA37474C2EFBF8B30102030405060708090A0B0C0D0E0F10", 0),
                new Case(Algorithm._T_TRIPLE_DES, CLEAR_KEY_16, 8), new Case(Algorithm._T_TRIPLE_DES, CLEAR_KEY_24, 0) };

        for (Case c : cases) {
            Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                    Export.E_EXPORTABLE_UNDER_TRUSTED_KEY, c.algorithm(), KeyUseFor.E_ENCRYPT_ONLY, "00");

            TR31KeyBlock kb = new TR31KeyBlock(header);
            kb.setClearKey(Bytes.parseHex(c.key()));
            kb.enforceKeyLengthObfuscationPadding();

            if (c.expectedPadding() == 0) {
                // Nothing to hide, the key is already at its maximum length
                assertEquals(null, kb.getClearKeyPadding(), "algorithm " + c.algorithm());
            }
            else {
                assertEquals(c.expectedPadding(), kb.getClearKeyPadding()
                                                      .length(), "algorithm " + c.algorithm());
            }
        }
    }
}
