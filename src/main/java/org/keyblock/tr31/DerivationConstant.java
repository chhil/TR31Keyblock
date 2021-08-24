package org.keyblock.tr31;

/**
 * CMAC key derivation constants can be created for the type of key we are
 * deriving. A helper class to set up key counter,keyusage and algorithm.
 *
 * @author murtuzachhil
 *
 */
public class DerivationConstant {
    public static final class _POS01_COUNTER {
        public static final String _01 = "01";
        public static final String _02 = "02";
        public static final String _03 = "03";
    }

    public static final class _POS02_KEYUSAGE {
        public static final String _0000_ENCRYPTION = "0000";
        public static final String _0001_MAC        = "0001";
    }

    public static final String _POS03_00_SEPATATOR = "00";

    public static final class _POS04_ALGORITHM {
        public static final String _0000_2TDEA  = "0000";
        public static final String _0001_3TDEA  = "0001";
        public static final String _0002_AES128 = "0002";
        public static final String _0003_AES192 = "0003";
        public static final String _0004_AES256 = "0004";

    }

    public static final class _POS05_KEYLENGTH {

        public static final String _0080_2TDEA  = "0080";
        public static final String _00C0_3TDEA  = "00C0";
        public static final String _0080_AES128 = "0080";
        public static final String _00C0_AES192 = "00C0";
        public static final String _0100_AES256 = "0100";

    }

}
