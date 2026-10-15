package org.keyblock.tr31;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import at.favre.lib.bytes.Bytes;

class KeyUtilitiesTest {

    @Test
    @DisplayName("Odd parity is set on every byte of a DES key")
    void oddParityIsApplied() {
        // Every byte here has even parity, so the least significant bit of each is flipped
        byte[] key = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        assertFalse(DesKeys.hasOddParity(key));
        byte[] adjusted = DesKeys.withOddParity(key);
        assertTrue(DesKeys.hasOddParity(adjusted));
        assertEquals("0101010101010101", Bytes.from(adjusted)
                                            .encodeHex());

        // A key that already has odd parity is returned unchanged
        byte[] alreadyOdd = adjusted.clone();
        assertTrue(java.util.Arrays.equals(alreadyOdd, DesKeys.withOddParity(alreadyOdd)));
    }

    @Test
    @DisplayName("Parity adjustment does not modify the argument")
    void parityAdjustmentDoesNotMutate() {
        byte[] key = Bytes.parseHex("3F419E1BC7E02000")
                         .array();
        byte[] copy = key.clone();
        DesKeys.withOddParity(key);
        assertTrue(java.util.Arrays.equals(copy, key));
    }

    @Test
    @DisplayName("Parity adjustment accepts double and triple length keys")
    void parityAcceptsAllDesLengths() {
        for (int length : new int[] { 8, 16, 24 }) {
            byte[] key = new byte[length];
            new java.util.Random(length)
                    .nextBytes(key);
            assertTrue(DesKeys.hasOddParity(DesKeys.withOddParity(key)), "length " + length);
        }
        assertThrows(IllegalArgumentException.class, () -> DesKeys.withOddParity(new byte[12]));
        assertThrows(IllegalArgumentException.class, () -> DesKeys.withOddParity(new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> DesKeys.withOddParity(null));
    }

    @Test
    @DisplayName("Generated key block protection keys have the length the type requires")
    void generatedKbpkLengths() {
        assertEquals(16, Bytes.parseHex(RandomKeys.generateKBPK(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, 128))
                                .length());
        assertEquals(24, Bytes.parseHex(RandomKeys.generateKBPK(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, 192))
                                .length());
        assertEquals(16, Bytes.parseHex(RandomKeys.generateKBPK(KeyblockType._D_AES_KEY_DERIVATION, 128))
                                .length());
        assertEquals(24, Bytes.parseHex(RandomKeys.generateKBPK(KeyblockType._D_AES_KEY_DERIVATION, 192))
                                .length());
        assertEquals(32, Bytes.parseHex(RandomKeys.generateKBPK(KeyblockType._D_AES_KEY_DERIVATION, 256))
                                .length());
        assertEquals(24, Bytes.parseHex(
                RandomKeys.generateKBPK(KeyblockType._E_ISO20038_AES_KEY_DERIVATION, 192))
                                .length());

        // Invalid lengths are refused rather than silently producing a key that cannot be used
        assertThrows(IllegalArgumentException.class,
                () -> RandomKeys.generateKBPK(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, 256));
        assertThrows(IllegalArgumentException.class,
                () -> RandomKeys.generateKBPK(KeyblockType._D_AES_KEY_DERIVATION, 64));
    }

    @Test
    @DisplayName("Generated clear keys have the length the algorithm requires")
    void generatedClearKeyLengths() {
        assertEquals(16, Bytes.parseHex(RandomKeys.generateClearKey(Algorithm._A_AES, 128))
                                .length());
        assertEquals(24, Bytes.parseHex(RandomKeys.generateClearKey(Algorithm._A_AES, 192))
                                .length());
        assertEquals(32, Bytes.parseHex(RandomKeys.generateClearKey(Algorithm._A_AES, 256))
                                .length());
        assertEquals(16, Bytes.parseHex(RandomKeys.generateClearKey(Algorithm._T_TRIPLE_DES, 128))
                                .length());
        assertEquals(24, Bytes.parseHex(RandomKeys.generateClearKey(Algorithm._T_TRIPLE_DES, 192))
                                .length());
        assertEquals(8, Bytes.parseHex(RandomKeys.generateClearKey(Algorithm._D_DEA, 64))
                                .length());

        assertThrows(IllegalArgumentException.class, () -> RandomKeys.generateClearKey(Algorithm._A_AES, 64));
        assertThrows(IllegalArgumentException.class,
                () -> RandomKeys.generateClearKey(Algorithm._T_TRIPLE_DES, 256));
    }

    @Test
    @DisplayName("Generated keys are not repeated")
    void generatedKeysDiffer() {
        String first = RandomKeys.generateKBPK(KeyblockType._D_AES_KEY_DERIVATION, 256);
        String second = RandomKeys.generateKBPK(KeyblockType._D_AES_KEY_DERIVATION, 256);
        assertNotEquals(first, second);
    }

    @Test
    @DisplayName("A key block built from generated keys round trips")
    void generatedKeysRoundTrip() throws Exception {
        String kbpk = RandomKeys.generateKBPK(KeyblockType._D_AES_KEY_DERIVATION, 256);
        String key = RandomKeys.generateClearKey(Algorithm._A_AES, 256);

        Header header = new Header(KeyblockType._D_AES_KEY_DERIVATION, KeyUsage._P0_PIN_ENCRYPTION,
                Export.N_NON_EXPORTABLE, Algorithm._A_AES, KeyUseFor.E_ENCRYPT_ONLY, "00");

        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex(key));
        kb.setKBPK(kbpk);
        kb.generate();

        TR31KeyBlock decrypted = new TR31KeyBlock();
        decrypted.decryptKeyBlock(kb.toString(), kbpk);
        assertEquals(Bytes.parseHex(key), decrypted.getClearKey());
    }
}