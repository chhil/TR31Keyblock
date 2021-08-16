package org.keyblock.tr31;

public enum KeyblockType {
                          A_VARIANT("A"),
                          B_Derivation("B");

    private String type;

    KeyblockType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
