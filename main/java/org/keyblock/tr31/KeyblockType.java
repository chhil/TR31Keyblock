package org.keyblock.tr31;

public enum KeyblockType {
                          /**
                           * Use of A has been deprecated. Use C.
                           */
                          A_KEY_VARIANT_BINDING("A"),
                          B_TDEA_KEY_DERIVATION_BINDING("B"),
                          C_TDEA_KEY_VARIANT_BINDING("C"),
                          D_AES_KEY_DERIVATION("D");

    private String type;

    KeyblockType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
