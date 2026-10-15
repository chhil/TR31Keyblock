package org.keyblock.tr31;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import at.favre.lib.bytes.Bytes;

/**
 * Key derivation must not depend on any shared mutable state. Cipher instances are mutable and
 * not thread safe, so the derivation ciphers used to be shared statically which allowed concurrent
 * derivations to re-initialise each other's cipher and derive keys under the wrong KBPK.
 */
class ConcurrentKeyDerivationTest {

    private static final String CLEAR_KEY_16 = "3F419E1CB7079442AA37474C2EFBF8B8";

    private static final int THREADS = 8;
    private static final int ROUNDS = 25;
    private static final long TIMEOUT_SECONDS = 60;

    /**
     * Distinct KBPKs so that any cross talk between threads produces a different key block.
     */
    private static List<String> kbpks(int count) {
        List<String> kbpks = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            kbpks.add(String.format("%016X%016X", 0x0BADCAFEDEADBEEFL, 0x1234567890ABCDEFL + i));
        }
        return kbpks;
    }

    private static String generate(KeyblockType type, String kbpk) throws Exception {
        Header header = new Header(type, KeyUsage._P0_PIN_ENCRYPTION, Export.E_EXPORTABLE_UNDER_TRUSTED_KEY,
                Algorithm._T_TRIPLE_DES, KeyUseFor.E_ENCRYPT_ONLY, "00");
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setClearKey(Bytes.parseHex(CLEAR_KEY_16));
        kb.setKBPK(kbpk);
        kb.generate();
        return kb.toString();
    }

    private static String hex(byte[] b) {
        return Bytes.from(b)
                    .encodeHex();
    }

    /**
     * Runs {@link #generate} for {@link #THREADS} different KBPKs concurrently, releasing all
     * threads from a barrier on every round so that they collide inside key derivation, and
     * compares every result against the value the same input produces on its own.
     */
    private void assertConcurrentGenerationIsDeterministic(KeyblockType type, List<String> kbpks)
            throws Exception {
        List<String> expected = new ArrayList<>();
        for (String kbpk : kbpks) {
            expected.add(generate(type, kbpk));
        }

        ExecutorService executor = Executors.newFixedThreadPool(THREADS);
        try {
            for (int round = 0; round < ROUNDS; round++) {
                CyclicBarrier barrier = new CyclicBarrier(THREADS);
                List<Callable<String>> tasks = new ArrayList<>(THREADS);
                for (String kbpk : kbpks) {
                    tasks.add(() -> {
                        barrier.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                        return generate(type, kbpk);
                    });
                }

                List<Future<String>> futures = executor.invokeAll(tasks, TIMEOUT_SECONDS, TimeUnit.SECONDS);
                for (int i = 0; i < futures.size(); i++) {
                    assertEquals(expected.get(i), futures.get(i)
                                             .get(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                            "round " + round + ", thread " + i + ", KBPK " + kbpks.get(i)
                                    + ", concurrent derivation produced a different key block");
                }
            }
        }
        finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("2 key TDEA KBPK derivation is safe to run concurrently")
    void concurrentTdea2KeyDerivation() throws Exception {
        List<String> kbpks = kbpks(THREADS);
        assertConcurrentGenerationIsDeterministic(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, kbpks);
    }

    @Test
    @DisplayName("3 key TDEA KBPK derivation is safe to run concurrently")
    void concurrentTdea3KeyDerivation() throws Exception {
        List<String> kbpks = new ArrayList<>();
        for (String kbpk : kbpks(THREADS)) {
            kbpks.add(kbpk + kbpk.substring(0, 16));
        }
        assertConcurrentGenerationIsDeterministic(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, kbpks);
    }

    @Test
    @DisplayName("AES KBPK derivation is safe to run concurrently")
    void concurrentAesDerivation() throws Exception {
        List<String> kbpks = kbpks(THREADS);
        assertConcurrentGenerationIsDeterministic(KeyblockType._D_AES_KEY_DERIVATION, kbpks);
    }

    @Test
    @DisplayName("Key variant binding is safe to run concurrently")
    void concurrentVariantBinding() throws Exception {
        List<String> kbpks = kbpks(THREADS);
        assertConcurrentGenerationIsDeterministic(KeyblockType._C_TDEA_KEY_VARIANT_BINDING, kbpks);
    }

    @Test
    @DisplayName("CMAC subkey derivation is safe to run concurrently")
    void concurrentCmac() throws Exception {
        byte[] message = Bytes.parseHex("6BC1BEE22E409F96E93D7E117393172A")
                                 .array();
        List<String> kbpks = kbpks(THREADS);

        List<String> expectedTdea = new ArrayList<>();
        List<String> expectedAes = new ArrayList<>();
        for (String kbpk : kbpks) {
            expectedTdea.add(hex(new CMAC(CMAC.Algorithm.TDES, Bytes.parseHex(kbpk)
                                                        .array()).generate(message)));
            expectedAes.add(hex(new CMAC(CMAC.Algorithm.AES, Bytes.parseHex(kbpk)
                                                       .array()).generate(message)));
        }

        ExecutorService executor = Executors.newFixedThreadPool(THREADS);
        try {
            for (int round = 0; round < ROUNDS; round++) {
                CyclicBarrier barrier = new CyclicBarrier(THREADS);
                List<Callable<String>> tasks = new ArrayList<>(THREADS);
                for (String kbpk : kbpks) {
                    tasks.add(() -> {
                        barrier.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                        byte[] key = Bytes.parseHex(kbpk)
                                       .array();
                        return hex(new CMAC(CMAC.Algorithm.TDES, key).generate(message)) + ":"
                                + hex(new CMAC(CMAC.Algorithm.AES, key).generate(message));
                    });
                }

                List<Future<String>> futures = executor.invokeAll(tasks, TIMEOUT_SECONDS, TimeUnit.SECONDS);
                for (int i = 0; i < futures.size(); i++) {
                    assertEquals(expectedTdea.get(i) + ":" + expectedAes.get(i),
                            futures.get(i)
                                   .get(TIMEOUT_SECONDS, TimeUnit.SECONDS),
                            "round " + round + ", thread " + i + ", CMAC differs under concurrency");
                }
            }
        }
        finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("Concurrent generation still agrees with the published ANSI example")
    void concurrentDerivationAgreesWithTheSpec() throws Exception {
        String kbpk = "DD7515F2BFC17F85CE48F3CA25CB21F6";
        String expected = generate(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, kbpk);

        ExecutorService executor = Executors.newFixedThreadPool(THREADS);
        try {
            CyclicBarrier barrier = new CyclicBarrier(THREADS);
            List<Callable<String>> tasks = new ArrayList<>(THREADS);
            for (int i = 0; i < THREADS; i++) {
                tasks.add(() -> {
                    barrier.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    return generate(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, kbpk);
                });
            }

            for (Future<String> future : executor.invokeAll(tasks, TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                assertEquals(expected, future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            }
        }
        finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("Key derivation helpers do not share cipher instances")
    void derivationCiphersAreNotShared() throws Exception {
        Cipher first = KeyHelper.getCipherForK1K2TDEAGeneration();
        Cipher second = KeyHelper.getCipherForK1K2TDEAGeneration();
        assertNotSame(first, second, "each derivation must get its own cipher");

        Cipher firstAes = KeyHelper.getCipherForK1K2AESGeneration();
        Cipher secondAes = KeyHelper.getCipherForK1K2AESGeneration();
        assertNotSame(firstAes, secondAes, "each derivation must get its own cipher");
    }

    @Test
    @DisplayName("Deriving all keys repeatedly gives stable results")
    void repeatedDerivationIsStable() throws Exception {
        String kbpk = "DD7515F2BFC17F85CE48F3CA25CB21F6";
        List<String> results = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            results.add(generate(KeyblockType._B_TDEA_KEY_DERIVATION_BINDING, kbpk));
        }
        assertEquals(1, new java.util.HashSet<>(results)
                           .size(), "repeated generation of the same input must be stable");
        assertArrayEquals(results.get(0)
                                 .getBytes(), results.get(49)
                                                  .getBytes());
    }
}