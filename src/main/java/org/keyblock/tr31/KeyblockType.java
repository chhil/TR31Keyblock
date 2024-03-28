package org.keyblock.tr31;

import java.util.Optional;

/**
 * Types A, B, C and D are defined by TR-31, numeric values are reserved for proprietary use.
 */
public enum KeyblockType {
                          /**
                           * Use of A has been deprecated. Use C.
                           */
                          _A_KEY_VARIANT_BINDING("A", 4),
                          _B_TDEA_KEY_DERIVATION_BINDING("B", 8),
                          _C_TDEA_KEY_VARIANT_BINDING("C", 4),
                          _D_AES_KEY_DERIVATION("D", 16),
                          _0_THALES_DES("0", 4),
                          _1_THALES_AES("1", 16);

    private final String type;
    private final int macLen;

    KeyblockType(String type, int macLen) {
        this.type = type;
        this.macLen = macLen;
    }

    public String getType() {
        return type;
    }

    public static Optional<KeyblockType> fromString(String blockTypeString) {
        // iterate over enums using for loop
        for (KeyblockType s : KeyblockType.values()) {
            if (blockTypeString.equals(s.getType())) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }

    public int getMACLen() {
        return macLen;
    }

    public boolean isAES() {
        switch (this) {
            case _D_AES_KEY_DERIVATION:
            //$FALL-THROUGH$
            case _1_THALES_AES: {
                return true;
            }
            default:
                return false;
        }
    }

    public int getCipherBlockSize() {
        if (isAES()) {
            return 16;
        } else {
            return 8;
        }
    }
}
