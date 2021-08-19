package org.keyblock.utils;

import java.nio.charset.StandardCharsets;

public class Util {

    public static byte[] hexStringToByteArray(String s) throws Exception {
        int len = s.length();
        if (s.length() % 2 != 0) {
            throw new Exception("Hex string length needs to be even number. Length is " + s.length());
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);

    public static String bytesToHexString(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.ISO_8859_1);
    }

    /**
     * Source JPOS ISOUtil.padleft
     * pad to the left
     *
     * @param s
     *            - original string
     * @param len
     *            - desired len
     * @param c
     *            - padding char
     * @return padded string
     * @throws Exception
     *             on error
     */
    public static String padleft(String s, int len, char c) throws Exception {
        s = s.trim();
        if (s.length() > len) {
            throw new Exception("invalid len " + s.length() + "/" + len);
        }
        StringBuilder d = new StringBuilder(len);
        int fill = len - s.length();
        while (fill-- > 0) {
            d.append(c);
        }
        d.append(s);
        return d.toString();
    }

    // https://android.googlesource.com/platform/frameworks/base.git/+/jb-mr1-release/core/java/com/android/internal/util/HexDump.java
    public static String dumpHexString(byte[] array) {
        return dumpHexString(array, 0, array.length);
    }

    private final static char[] HEX_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
            'E', 'F' };

    public static String dumpHexString(byte[] array, int offset, int length) {
        StringBuilder result = new StringBuilder();

        byte[] line = new byte[16];
        int lineIndex = 0;

        result.append("\n0x");
        result.append(toHexString(offset));

        for (int i = offset; i < offset + length; i++) {
            if (lineIndex == 16) {
                result.append(" ");

                for (int j = 0; j < 16; j++) {
                    if (line[j] > ' ' && line[j] < '~') {
                        result.append(new String(line, j, 1));
                    }
                    else {
                        result.append(".");
                    }
                }

                result.append("\n0x");
                result.append(toHexString(i));
                lineIndex = 0;
            }

            byte b = array[i];
            result.append(" ");
            result.append(HEX_DIGITS[(b >>> 4) & 0x0F]);
            result.append(HEX_DIGITS[b & 0x0F]);

            line[lineIndex] = b;
            lineIndex++;
        }

        if (lineIndex != 16) {
            int count = (16 - lineIndex) * 3;
            count++;
            for (int i = 0; i < count; i++) {
                result.append(" ");
            }

            for (int i = 0; i < lineIndex; i++) {
                if (line[i] > ' ' && line[i] < '~') {
                    result.append(new String(line, i, 1));
                }
                else {
                    result.append(".");
                }
            }
        }

        return result.toString();
    }

    public static String toHexString(int i) {
        return toHexString(toByteArray(i));
    }

    public static byte[] toByteArray(int i) {
        byte[] array = new byte[4];

        array[3] = (byte) (i & 0xFF);
        array[2] = (byte) ((i >> 8) & 0xFF);
        array[1] = (byte) ((i >> 16) & 0xFF);
        array[0] = (byte) ((i >> 24) & 0xFF);

        return array;
    }

    public static String toHexString(byte[] array) {
        return toHexString(array, 0, array.length);
    }

    public static String toHexString(byte[] array, int offset, int length) {
        char[] buf = new char[length * 2];
        int bufIndex = 0;
        for (int i = offset; i < offset + length; i++) {
            byte b = array[i];
            buf[bufIndex] = HEX_DIGITS[(b >>> 4) & 0x0F];
            bufIndex++;
            buf[bufIndex] = HEX_DIGITS[b & 0x0F];
            bufIndex++;
        }
        return new String(buf);
    }
    /////// END Hexdump

    // Logic taken from JPOS ISOUtil.xor
    public static byte[] xor(byte[] op1, byte[] op2) {
        byte[] result;
        // Use the smallest array
        if (op2.length > op1.length) {
            result = new byte[op1.length];
        }
        else {
            result = new byte[op2.length];
        }
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (op1[i] ^ op2[i]);
        }
        return result;

    }

    public static byte[] shiftLeft(byte[] bytes) {
        byte[] result = bytes.clone();
        for (int i = 0; i < result.length; i++) {
            result[i] <<= 1;
            if (i < result.length - 1) {
                result[i] |= (result[i + 1] >> 7) & 1;
            }
        }
        return result;
    }
}
