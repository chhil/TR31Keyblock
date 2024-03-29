package org.keyblock.tr31;

import java.util.Optional;

public enum KeyUseFor {

                       B_BOTH_ENCRYPT_AND_DECRYPT("B"),
                       C_MAC_CALCULATE_GENERATE_OR_VERIFY("C"),
                       D_DECRYPT_ONLY("D"),
                       E_ENCRYPT_ONLY("E"),
                       G_MAC_GENERATE_ONLY("G"),
                       N_NO_SPECIAL_RESTRICTIONS_OR_NOT_APPLICABLE("N"),
                       S_SIGNATURE_ONLY("S"),
                       T_SIGN_AND_DECYPT("T"),
                       V_MAC_VERIFY_ONLY("V"),
                       X_DERIVE_OTHER_KEYS("X"),
                       Y_CREATE_KEY_VARIANTS("Y");

    private final String useFor;

    KeyUseFor(String use) {
        this.useFor = use;
    }

    public String get() {
        return useFor;
    }

    public static Optional<KeyUseFor> fromString(String keyUseFor) {

        // iterate over enums using for loop
        for (KeyUseFor s : KeyUseFor.values()) {
            if (keyUseFor.equals(s.get())) {
                return Optional.of(s);
            }
        }
        return Optional.empty();

    }

}
