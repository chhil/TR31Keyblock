package org.keyblock.tr31;

import java.util.Optional;

/**
 * Various optional block types defined in ASC X9 TR 31-2018 and/or ANSI X9.143-2022. Numeric
 * values are reserved for proprietary use.
 */
public enum DefinedOptionalBlockType {

    /**
     * Asymmetric key life attribute.
     */
    _AL("AL"),
    /**
     * Base Derviation Key Identifier for DUKPT type keys.
     */
    _BI("BI"),
    /**
     * Asymmetric public key certificate or chain of certificates.
     */
    _CT("CT"),
    /**
     * Derivation(s) Allowed for Derivation Keys.
     */
    _DA("DA"),
    /**
     * Hash algorithm for HMAC type wrapped key.
     */
    _HM("HM"),
    /**
     * Identifier for the Initial AES DUKPT Key.
     */
    _IK("IK"),
    /**
     * Key check value of the wrapped key.
     */
    _KC("KC"),
    /**
     * Key check value of the KBPK.
     */
    _KP("KP"),
    /**
     * Initial Key Serial Number for TDEA DUKPT.
     */
    _KS("KS"),
    /**
     * Key Block Values Version
     */
    _KV("KV"),
    /**
     * Label
     */
    _LB("LB"),
    /**
     * Proprietary Algorithm
     */
    _PA("PA"),
    /**
     * A variable-length padding field used as the last Optional Block.
     */
    _PB("PB"),
    /**
     * Time key wrapped in key block was created.
     */
    _TC("TC"),
    /**
     * Time key block itself was created.
     */
    _TS("TS"),
    ;

    private final String id;

    DefinedOptionalBlockType(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public static Optional<DefinedOptionalBlockType> fromString(String idString) {
        // iterate over enums using for loop
        for (DefinedOptionalBlockType s : DefinedOptionalBlockType.values()) {
            if (s.getId().equals(idString)) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }

}
