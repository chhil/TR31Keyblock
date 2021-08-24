package org.keyblock.tr31;

import java.util.Optional;

public enum KeyblockType {
                          /**
                           * Use of A has been deprecated. Use C.
                           */
                          _A_KEY_VARIANT_BINDING("A"),
                          _B_TDEA_KEY_DERIVATION_BINDING("B"),
                          _C_TDEA_KEY_VARIANT_BINDING("C"),
                          _D_AES_KEY_DERIVATION("D"),
                          _0_THALES_DES("0"),
                          _1_THALES_AES("1");

    private String type;

    KeyblockType(String type) {
        this.type = type;
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
}
