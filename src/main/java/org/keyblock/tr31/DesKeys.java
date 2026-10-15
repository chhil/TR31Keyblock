package org.keyblock.tr31;

import java.util.Arrays;

/**
 * DES key helpers.
 * <p>
 * DES keys carry odd parity in the least significant bit of each byte. The parity bit does not
 * affect the result of the cipher, but keys are conventionally stored with odd parity and some
 * HSMs reject keys without it.
 */
public final class DesKeys {

    private DesKeys() { }

    /**
     * True when every byte of the key has odd parity, that is an odd number of set bits.
     */
    public static boolean hasOddParity(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }
        for (byte b : key) {
            if (Integer.bitCount(b & 0xFF) % 2 == 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns a copy of the key with odd parity set on every byte. Double and triple length keys
     * are accepted, any other length is rejected.
     *
     * @param key
     *            a single (8), double (16) or triple (24) length DES key
     * @return a new array, the argument is not modified
     */
    public static byte[] withOddParity(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }
        if (key.length != 8 && key.length != 16 && key.length != 24) {
            throw new IllegalArgumentException(
                    "A DES key must be 8, 16 or 24 bytes but was " + key.length);
        }

        byte[] adjusted = Arrays.copyOf(key, key.length);
        for (int i = 0; i < adjusted.length; i++) {
            if (Integer.bitCount(adjusted[i] & 0xFF) % 2 == 0) {
                adjusted[i] ^= 1;
            }
        }
        return adjusted;
    }

    /**
     * Hexadecimal convenience form of {@link #withOddParity(byte[])}.
     */
    public static String withOddParityHex(String hexKey) {
        byte[] key = at.favre.lib.bytes.Bytes.parseHex(hexKey.replace(" ", ""))
                                         .array();
        return at.favre.lib.bytes.Bytes.from(withOddParity(key))
                              .encodeHex(true);
    }
}