package org.keyblock.tr31;

public enum KeyUseFor {

                       B_Both_Encrypt_and_Decrypt("B"),
                       C_MAC_Calculate_Generate_or_Verify("C"),
                       D_Decrypt_only("D"),
                       E_Encrypt_only("E"),
                       G_MAC_Generate_only("G"),
                       N_No_special_restrictions_or_not_applicable("N"),
                       S_Signature_only("S"),
                       V_MAC_Verify_only("V");

    private String useFor;

    KeyUseFor(String use) {
        this.useFor = use;
        // TODO Auto-generated constructor stub
    }

    public String get() {
        return useFor;
    }
}
