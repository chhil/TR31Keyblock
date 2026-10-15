package org.keyblock.tr31;

/**
 * Validation of the key block header and optional blocks against the field formats defined by
 * ANSI X9.143:2021 section 4 and the optional block definitions in A.5.6.
 * <p>
 * The checks are deliberately limited to things the standard states unambiguously. Notably the
 * mode of use is <em>not</em> required to be one of the values allowed for the key usage, because
 * key blocks produced by real HSMs do not agree on that (the payShield examples wrap a B0 key with
 * mode of use N, for instance), and rejecting them would break interoperation for no benefit.
 */
final class KeyBlockValidation {

    private KeyBlockValidation() { }

    /**
     * Format codes from ANSI X9.143:2021, 4.
     */
    private enum Format {
        /** alphanumeric */
        AN,
        /** hexadecimal, upper case only */
        H,
        /** numeric */
        N,
        /** printable ASCII */
        PA,
        /** base64, as used by the CT optional block for the certificate */
        B64
    }

    static void validateHeader(String header) {
        requireLength(header, 16, "key block header");

        check(header, 0, 1, Format.AN, "key block version ID");
        check(header, 1, 5, Format.N, "key block length");
        check(header, 5, 7, Format.AN, "key usage");
        check(header, 7, 8, Format.AN, "algorithm");
        check(header, 8, 9, Format.AN, "mode of use");
        check(header, 9, 11, Format.AN, "key version number");
        check(header, 11, 12, Format.AN, "exportability");
        check(header, 12, 14, Format.N, "number of optional blocks");
        check(header, 14, 16, Format.AN, "reserved");

        if (!header.substring(14, 16)
                      .equals("00")) {
            throw new IllegalArgumentException("Reserved header field must be '00' but was '"
                    + header.substring(14, 16) + "'");
        }
    }

    static void validateOptionalBlockId(String id) {
        if (id.length() != 2 || !isAlphanumeric(id)) {
            throw new IllegalArgumentException(
                    "Optional block ID '" + id + "' must be 2 alphanumeric characters");
        }
    }

    /**
     * Key length checks for the symmetric algorithms, see ANSI X9.143:2021 6.3.2. Asymmetric keys
     * carry an ASN.1 DER encoding of any length and are not checked here.
     */
    static void validateKeyLength(Algorithm algorithm, int keyLengthBytes) {
        switch (algorithm) {
            case _A_AES: {
                if (keyLengthBytes != 16 && keyLengthBytes != 24 && keyLengthBytes != 32) {
                    throw new IllegalArgumentException(
                            "An AES key must be 16, 24 or 32 bytes but was " + keyLengthBytes);
                }
                break;
            }
            case _T_TRIPLE_DES: {
                if (keyLengthBytes != 16 && keyLengthBytes != 24) {
                    throw new IllegalArgumentException(
                            "A TDEA key must be 16 or 24 bytes but was " + keyLengthBytes);
                }
                break;
            }
            case _D_DEA: {
                if (keyLengthBytes != 8) {
                    throw new IllegalArgumentException("A DES key must be 8 bytes but was " + keyLengthBytes);
                }
                break;
            }
            default: {
                // RSA, ECC, DSA and HMAC keys carry an encoding whose length is not fixed
                break;
            }
        }
    }

    /**
     * @param strictOptionalBlockData
     *            when false only the structure of the optional block is checked, when true the
     *            data is also checked against the character format required for that ID. Defaults
     *            to false because real key blocks do not always comply, the example published in
     *            ANSI X9.143:2021 section 8.2 has a KS optional block whose data is not
     *            hexadecimal. Turn it on when the sender is not trusted.
     */
    static void validateOptionalBlock(String id, String data, boolean strictOptionalBlockData) {
        validateOptionalBlockId(id);

        if (!strictOptionalBlockData) {
            return;
        }

        Format format = dataFormat(id);
        if (format == null) {
            // Unknown or proprietary ID, ANSI X9.143:2021 A.5.6 requires a device that does not
            // understand the ID to reject the block, but the ID may legitimately be a proprietary
            // value, so only the structure is checked here.
            return;
        }

        if (!matches(data, format)) {
            throw new IllegalArgumentException("Optional block '" + id + "' data '" + data
                    + "' is not a valid " + format.name() + " value");
        }
    }

    /**
     * The data format required for the optional blocks with a defined ID, see ANSI X9.143:2021
     * A.5.6. Returns null when the ID is not one this implementation knows the format of.
     */
    private static Format dataFormat(String id) {
        switch (id) {
            // Hexadecimal, for example a key set identifier or a key check value
            case "AL":
            case "BI":
            case "HM":
            case "IK":
            case "KC":
            case "KP":
            case "KS":
            case "PK": {
                return Format.H;
            }
            // Alphanumeric
            case "DA":
            case "LB":
            case "PA": {
                return Format.AN;
            }
            // The padding block holds readable ASCII characters
            case "PB": {
                return Format.PA;
            }
            // base64 encoded DER, preceded by a 2 character certificate format indicator
            case "CT": {
                return Format.B64;
            }
            // Timestamps and unstructured printable data
            case "TC":
            case "TS":
            case "KV": {
                return Format.PA;
            }
            default: {
                return null;
            }
        }
    }

    private static void requireLength(String value, int length, String what) {
        if (value.length() < length) {
            throw new IllegalArgumentException("The " + what + " must be at least " + length
                    + " characters but was " + value.length());
        }
    }

    private static void check(String value, int start, int end, Format format, String field) {
        String fieldValue = value.substring(start, end);
        if (!matches(fieldValue, format)) {
            throw new IllegalArgumentException("Header field " + field + " '" + fieldValue
                    + "' is not a valid " + format.name() + " value");
        }
    }

    private static boolean matches(String value, Format format) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (format) {
                case AN: {
                    if (!isAlphanumericChar(c)) {
                        return false;
                    }
                    break;
                }
                case H: {
                    if (!isHexDigit(c)) {
                        return false;
                    }
                    break;
                }
                case N: {
                    if (c < '0' || c > '9') {
                        return false;
                    }
                    break;
                }
                case PA: {
                    if (c < 0x20 || c > 0x7E) {
                        return false;
                    }
                    break;
                }
                case B64: {
                    if (!isBase64Char(c)) {
                        return false;
                    }
                    break;
                }
                default: {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean isAlphanumeric(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!isAlphanumericChar(value.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isAlphanumericChar(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    /**
     * The base64 alphabet plus the '=' padding character, see RFC 4648. Both cases are allowed, base64
     * is not an upper case only format.
     */
    private static boolean isBase64Char(char c) {
        return isAlphanumericChar(c) || c == '+' || c == '/' || c == '=';
    }

    /**
     * ANSI X9.143:2021 4 format H is upper case hexadecimal only, lower case is not a valid
     * encoding for these fields.
     */
    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
    }
}