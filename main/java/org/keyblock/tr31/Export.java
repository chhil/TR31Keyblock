package org.keyblock.tr31;

public enum Export {

                    E_Exportable_under_trusted_key("E"),
                    N_Non_exportable("N"),
                    S_Sensitive_Exportable_under_untrusted_key("S");

    private String type;

    Export(String type) {
        this.type = type;
    }

    public String get() {
        return this.type;
    }

}
