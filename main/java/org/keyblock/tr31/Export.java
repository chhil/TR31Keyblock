package org.keyblock.tr31;

import java.util.Optional;

public enum Export {

                    E_EXPORTABLE_UNDER_TRUSTED_KEY("E"),
                    N_NON_EXPORTABLE("N"),
                    S_SENSITIVE_EXPORTABLE_UNDER_UNTRUSTED_KEY("S");

    private String type;

    Export(String type) {
        this.type = type;
    }

    public String get() {
        return this.type;
    }

    public static Optional<Export> fromString(String exportString) {

        // iterate over enums using for loop
        for (Export s : Export.values()) {
            if (exportString.equals(s.get())) {
                return Optional.of(s);
            }
        }
        return Optional.empty();

    }

}
