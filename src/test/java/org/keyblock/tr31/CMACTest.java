package org.keyblock.tr31;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * Test data taken from mbedTLS.
 */
public class CMACTest {

    private static final int NUM_ITER = 4;

    static final int[] des3_message_lengths = {
            0,
            16,
            20,
            32
    };

    /* All CMAC test inputs are truncated from the same 64 byte buffer. */
    static final byte[] test_message = {
            /* PT */
            (byte) 0x6b, (byte) 0xc1, (byte) 0xbe, (byte) 0xe2,     (byte) 0x2e, (byte) 0x40, (byte) 0x9f, (byte) 0x96,
            (byte) 0xe9, (byte) 0x3d, (byte) 0x7e, (byte) 0x11,     (byte) 0x73, (byte) 0x93, (byte) 0x17, (byte) 0x2a,
            (byte) 0xae, (byte) 0x2d, (byte) 0x8a, (byte) 0x57,     (byte) 0x1e, (byte) 0x03, (byte) 0xac, (byte) 0x9c,
            (byte) 0x9e, (byte) 0xb7, (byte) 0x6f, (byte) 0xac,     (byte) 0x45, (byte) 0xaf, (byte) 0x8e, (byte) 0x51,
            (byte) 0x30, (byte) 0xc8, (byte) 0x1c, (byte) 0x46,     (byte) 0xa3, (byte) 0x5c, (byte) 0xe4, (byte) 0x11,
            (byte) 0xe5, (byte) 0xfb, (byte) 0xc1, (byte) 0x19,     (byte) 0x1a, (byte) 0x0a, (byte) 0x52, (byte) 0xef,
            (byte) 0xf6, (byte) 0x9f, (byte) 0x24, (byte) 0x45,     (byte) 0xdf, (byte) 0x4f, (byte) 0x9b, (byte) 0x17,
            (byte) 0xad, (byte) 0x2b, (byte) 0x41, (byte) 0x7b,     (byte) 0xe6, (byte) 0x6c, (byte) 0x37, (byte) 0x10
    };

    /* CMAC-TDES (Generation) - 2 Key Test Data */
    static final byte[] des3_2key_key = {
            /* Key1 */
            (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,     (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
            /* Key2 */
            (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,     (byte) 0xab, (byte) 0xcd, (byte) 0xEF, (byte) 0x01,
    };

    static final byte[][] des3_2key_expected_result = {
            {
                    /* Sample #1 */
                    (byte) 0x79, (byte) 0xce, (byte) 0x52, (byte) 0xa7,     (byte) 0xf7, (byte) 0x86, (byte) 0xa9, (byte) 0x60
            },
            {
                    /* Sample #2 */
                    (byte) 0xcc, (byte) 0x18, (byte) 0xa0, (byte) 0xb7,     (byte) 0x9a, (byte) 0xf2, (byte) 0x41, (byte) 0x3b
            },
            {
                    /* Sample #3 */
                    (byte) 0xc0, (byte) 0x6d, (byte) 0x37, (byte) 0x7e,     (byte) 0xcd, (byte) 0x10, (byte) 0x19, (byte) 0x69
            },
            {
                    /* Sample #4 */
                    (byte) 0x9c, (byte) 0xd3, (byte) 0x35, (byte) 0x80,     (byte) 0xf9, (byte) 0xb6, (byte) 0x4d, (byte) 0xfb
            }
    };

    /* CMAC-TDES (Generation) - 3 Key Test Data */
    static final byte[] des3_3key_key = {
        /* Key1 */
        (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67,     (byte) 0x89, (byte) 0xaa, (byte) 0xcd, (byte) 0xef,
        /* Key2 */
        (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,     (byte) 0xab, (byte) 0xcd, (byte) 0xef, (byte) 0x01,
        /* Key3 */
        (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xab,     (byte) 0xcd, (byte) 0xef, (byte) 0x01, (byte) 0x23
    };
    static final byte[][] des3_3key_subkeys = {
        {
            /* K1 */
            (byte) 0x9d, (byte) 0x74, (byte) 0xe7, (byte) 0x39,     (byte) 0x33, (byte) 0x17, (byte) 0x96, (byte) 0xc0
        },
        {
            /* K2 */
            (byte) 0x3a, (byte) 0xe9, (byte) 0xce, (byte) 0x72,     (byte) 0x66, (byte) 0x2f, (byte) 0x2d, (byte) 0x9b
        }
    };
    static final byte[][] des3_3key_expected_result = {
        {
            /* Sample #1 */
            (byte) 0x7d, (byte) 0xb0, (byte) 0xd3, (byte) 0x7d,     (byte) 0xf9, (byte) 0x36, (byte) 0xc5, (byte) 0x50
        },
        {
            /* Sample #2 */
            (byte) 0x30, (byte) 0x23, (byte) 0x9c, (byte) 0xf1,     (byte) 0xf5, (byte) 0x2e, (byte) 0x66, (byte) 0x09
        },
        {
            /* Sample #3 */
            (byte) 0x6c, (byte) 0x9f, (byte) 0x3e, (byte) 0xe4,     (byte) 0x92, (byte) 0x3f, (byte) 0x6b, (byte) 0xe2
        },
        {
            /* Sample #4 */
            (byte) 0x99, (byte) 0x42, (byte) 0x9b, (byte) 0xd0,     (byte) 0xbF, (byte) 0x79, (byte) 0x04, (byte) 0xe5
        }
    };

    @Test
    void testTdes2keyCmac() throws Exception {
        for (int i = 0; i < NUM_ITER; i++) {
            byte[] message = new byte[des3_message_lengths[i]];
            System.arraycopy(test_message, 0, message, 0, message.length);
            byte[] cmacResult = new CMAC(CMAC.Algorithm.TDES, des3_2key_key).generate(message);
            assertArrayEquals(des3_2key_expected_result[i], cmacResult);
        }
    }

    @Test
    void testTdes3keyCmac() throws Exception {
        for (int i = 0; i < NUM_ITER; i++) {
            byte[] message = new byte[des3_message_lengths[i]];
            System.arraycopy(test_message, 0, message, 0, message.length);
            byte[] cmacResult = new CMAC(CMAC.Algorithm.TDES, des3_3key_key).generate(message);
            assertArrayEquals(des3_3key_expected_result[i], cmacResult);
        }
    }

    static final int[] aes_message_lengths = {
        /* Mlen */
        0,
        16,
        20,
        64
    };

    /* CMAC-AES128 Test Data */
    static final byte[] aes_128_key = {
        (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16,     (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
        (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88,     (byte) 0x09, (byte) 0xcf, (byte) 0x4f, (byte) 0x3c
    };

    static final byte[][] aes_128_subkeys = {
        {
            /* K1 */
            (byte) 0xfb, (byte) 0xee, (byte) 0xd6, (byte) 0x18,     (byte) 0x35, (byte) 0x71, (byte) 0x33, (byte) 0x66,
            (byte) 0x7c, (byte) 0x85, (byte) 0xe0, (byte) 0x8f,     (byte) 0x72, (byte) 0x36, (byte) 0xa8, (byte) 0xde
        },
        {
            /* K2 */
            (byte) 0xf7, (byte) 0xdd, (byte) 0xac, (byte) 0x30,     (byte) 0x6a, (byte) 0xe2, (byte) 0x66, (byte) 0xcc,
            (byte) 0xf9, (byte) 0x0b, (byte) 0xc1, (byte) 0x1e,     (byte) 0xe4, (byte) 0x6d, (byte) 0x51, (byte) 0x3b
        }
    };

    static final byte[][] aes_128_expected_result = {
        {
            /* Example #1 */
            (byte) 0xbb, (byte) 0x1d, (byte) 0x69, (byte) 0x29,     (byte) 0xe9, (byte) 0x59, (byte) 0x37, (byte) 0x28,
            (byte) 0x7f, (byte) 0xa3, (byte) 0x7d, (byte) 0x12,     (byte) 0x9b, (byte) 0x75, (byte) 0x67, (byte) 0x46
        },
        {
            /* Example #2 */
            (byte) 0x07, (byte) 0x0a, (byte) 0x16, (byte) 0xb4,     (byte) 0x6b, (byte) 0x4d, (byte) 0x41, (byte) 0x44,
            (byte) 0xf7, (byte) 0x9b, (byte) 0xdd, (byte) 0x9d,     (byte) 0xd0, (byte) 0x4a, (byte) 0x28, (byte) 0x7c
        },
        {
            /* Example #3 */
            (byte) 0x7d, (byte) 0x85, (byte) 0x44, (byte) 0x9e,     (byte) 0xa6, (byte) 0xea, (byte) 0x19, (byte) 0xc8,
            (byte) 0x23, (byte) 0xa7, (byte) 0xbf, (byte) 0x78,     (byte) 0x83, (byte) 0x7d, (byte) 0xfa, (byte) 0xde
        },
        {
            /* Example #4 */
            (byte) 0x51, (byte) 0xf0, (byte) 0xbe, (byte) 0xbf,     (byte) 0x7e, (byte) 0x3b, (byte) 0x9d, (byte) 0x92,
            (byte) 0xfc, (byte) 0x49, (byte) 0x74, (byte) 0x17,     (byte) 0x79, (byte) 0x36, (byte) 0x3c, (byte) 0xfe
        }
    };

    /* CMAC-AES192 Test Data */
    static final byte[] aes_192_key = {
        (byte) 0x8e, (byte) 0x73, (byte) 0xb0, (byte) 0xf7,     (byte) 0xda, (byte) 0x0e, (byte) 0x64, (byte) 0x52,
        (byte) 0xc8, (byte) 0x10, (byte) 0xf3, (byte) 0x2b,     (byte) 0x80, (byte) 0x90, (byte) 0x79, (byte) 0xe5,
        (byte) 0x62, (byte) 0xf8, (byte) 0xea, (byte) 0xd2,     (byte) 0x52, (byte) 0x2c, (byte) 0x6b, (byte) 0x7b
    };

    static final byte[][] aes_192_subkeys = {
        {
            /* K1 */
            (byte) 0x44, (byte) 0x8a, (byte) 0x5b, (byte) 0x1c,     (byte) 0x93, (byte) 0x51, (byte) 0x4b, (byte) 0x27,
            (byte) 0x3e, (byte) 0xe6, (byte) 0x43, (byte) 0x9d,     (byte) 0xd4, (byte) 0xda, (byte) 0xa2, (byte) 0x96
        },
        {
            /* K2 */
            (byte) 0x89, (byte) 0x14, (byte) 0xb6, (byte) 0x39,     (byte) 0x26, (byte) 0xa2, (byte) 0x96, (byte) 0x4e,
            (byte) 0x7d, (byte) 0xcc, (byte) 0x87, (byte) 0x3b,     (byte) 0xa9, (byte) 0xb5, (byte) 0x45, (byte) 0x2c
        }
    };

    static final byte[][] aes_192_expected_result = {
        {
            /* Example #1 */
            (byte) 0xd1, (byte) 0x7d, (byte) 0xdf, (byte) 0x46,     (byte) 0xad, (byte) 0xaa, (byte) 0xcd, (byte) 0xe5,
            (byte) 0x31, (byte) 0xca, (byte) 0xc4, (byte) 0x83,     (byte) 0xde, (byte) 0x7a, (byte) 0x93, (byte) 0x67
        },
        {
            /* Example #2 */
            (byte) 0x9e, (byte) 0x99, (byte) 0xa7, (byte) 0xbf,     (byte) 0x31, (byte) 0xe7, (byte) 0x10, (byte) 0x90,
            (byte) 0x06, (byte) 0x62, (byte) 0xf6, (byte) 0x5e,     (byte) 0x61, (byte) 0x7c, (byte) 0x51, (byte) 0x84
        },
        {
            /* Example #3 */
            (byte) 0x3d, (byte) 0x75, (byte) 0xc1, (byte) 0x94,     (byte) 0xed, (byte) 0x96, (byte) 0x07, (byte) 0x04,
            (byte) 0x44, (byte) 0xa9, (byte) 0xfa, (byte) 0x7e,     (byte) 0xc7, (byte) 0x40, (byte) 0xec, (byte) 0xf8
        },
        {
            /* Example #4 */
            (byte) 0xa1, (byte) 0xd5, (byte) 0xdf, (byte) 0x0e,     (byte) 0xed, (byte) 0x79, (byte) 0x0f, (byte) 0x79,
            (byte) 0x4d, (byte) 0x77, (byte) 0x58, (byte) 0x96,     (byte) 0x59, (byte) 0xf3, (byte) 0x9a, (byte) 0x11
        }
    };

    /* CMAC-AES256 Test Data */
    static final byte[] aes_256_key = {
        (byte) 0x60, (byte) 0x3d, (byte) 0xeb, (byte) 0x10,     (byte) 0x15, (byte) 0xca, (byte) 0x71, (byte) 0xbe,
        (byte) 0x2b, (byte) 0x73, (byte) 0xae, (byte) 0xf0,     (byte) 0x85, (byte) 0x7d, (byte) 0x77, (byte) 0x81,
        (byte) 0x1f, (byte) 0x35, (byte) 0x2c, (byte) 0x07,     (byte) 0x3b, (byte) 0x61, (byte) 0x08, (byte) 0xd7,
        (byte) 0x2d, (byte) 0x98, (byte) 0x10, (byte) 0xa3,     (byte) 0x09, (byte) 0x14, (byte) 0xdf, (byte) 0xf4
    };

    static final byte[][] aes_256_subkeys = {
        {
            /* K1 */
            (byte) 0xca, (byte) 0xd1, (byte) 0xed, (byte) 0x03,     (byte) 0x29, (byte) 0x9e, (byte) 0xed, (byte) 0xac,
            (byte) 0x2e, (byte) 0x9a, (byte) 0x99, (byte) 0x80,     (byte) 0x86, (byte) 0x21, (byte) 0x50, (byte) 0x2f
        },
        {
            /* K2 */
            (byte) 0x95, (byte) 0xa3, (byte) 0xda, (byte) 0x06,     (byte) 0x53, (byte) 0x3d, (byte) 0xdb, (byte) 0x58,
            (byte) 0x5d, (byte) 0x35, (byte) 0x33, (byte) 0x01,     (byte) 0x0c, (byte) 0x42, (byte) 0xa0, (byte) 0xd9
        }
    };

    static final byte[][] aes_256_expected_result = {
        {
            /* Example #1 */
            (byte) 0x02, (byte) 0x89, (byte) 0x62, (byte) 0xf6,     (byte) 0x1b, (byte) 0x7b, (byte) 0xf8, (byte) 0x9e,
            (byte) 0xfc, (byte) 0x6b, (byte) 0x55, (byte) 0x1f,     (byte) 0x46, (byte) 0x67, (byte) 0xd9, (byte) 0x83
        },
        {
            /* Example #2 */
            (byte) 0x28, (byte) 0xa7, (byte) 0x02, (byte) 0x3f,     (byte) 0x45, (byte) 0x2e, (byte) 0x8f, (byte) 0x82,
            (byte) 0xbd, (byte) 0x4b, (byte) 0xf2, (byte) 0x8d,     (byte) 0x8c, (byte) 0x37, (byte) 0xc3, (byte) 0x5c
        },
        {
            /* Example #3 */
            (byte) 0x15, (byte) 0x67, (byte) 0x27, (byte) 0xdc,     (byte) 0x08, (byte) 0x78, (byte) 0x94, (byte) 0x4a,
            (byte) 0x02, (byte) 0x3c, (byte) 0x1f, (byte) 0xe0,     (byte) 0x3b, (byte) 0xad, (byte) 0x6d, (byte) 0x93
        },
        {
            /* Example #4 */
            (byte) 0xe1, (byte) 0x99, (byte) 0x21, (byte) 0x90,     (byte) 0x54, (byte) 0x9f, (byte) 0x6e, (byte) 0xd5,
            (byte) 0x69, (byte) 0x6a, (byte) 0x2c, (byte) 0x05,     (byte) 0x6c, (byte) 0x31, (byte) 0x54, (byte) 0x10
        }
    };

    @Test
    void testAes128Cmac() throws Exception {
        for (int i = 0; i < NUM_ITER; i++) {
            byte[] message = new byte[aes_message_lengths[i]];
            System.arraycopy(test_message, 0, message, 0, message.length);
            byte[] cmacResult = new CMAC(CMAC.Algorithm.AES, aes_128_key).generate(message);
            assertArrayEquals(aes_128_expected_result[i], cmacResult);
        }
    }

    @Test
    void testAes192Cmac() throws Exception {
        for (int i = 0; i < NUM_ITER; i++) {
            byte[] message = new byte[aes_message_lengths[i]];
            System.arraycopy(test_message, 0, message, 0, message.length);
            byte[] cmacResult = new CMAC(CMAC.Algorithm.AES, aes_192_key).generate(message);
            assertArrayEquals(aes_192_expected_result[i], cmacResult);
        }
    }

    @Test
    void testAes256Cmac() throws Exception {
        for (int i = 0; i < NUM_ITER; i++) {
            byte[] message = new byte[aes_message_lengths[i]];
            System.arraycopy(test_message, 0, message, 0, message.length);
            byte[] cmacResult = new CMAC(CMAC.Algorithm.AES, aes_256_key).generate(message);
            assertArrayEquals(aes_256_expected_result[i], cmacResult);
        }
    }

}
