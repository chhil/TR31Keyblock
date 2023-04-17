package org.keyblock.tr31;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer;
import org.javatuples.Pair;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class CMAC {

    public enum Algorithm {
        TDES("DESede"),
        AES("AES"),
        ;

        final String jceAlgoString;

        Algorithm(String algoStr) {
            jceAlgoString = algoStr;
        }
    }

    private final Algorithm algo;
    private final SecretKeySpec key;
    private final Pair<Bytes, Bytes> subKeys;

    public CMAC(Algorithm algo, byte[] rawKey) throws Exception {
        this.algo = algo;

        SecretKeySpec key = new SecretKeySpec(rawKey, algo.jceAlgoString);
        if (algo == Algorithm.TDES) {
            key = KeyHelper.convertToTripleLengthKey(key);
        }

        switch (algo) {
            case TDES:
                subKeys = KeyHelper.generateCMACK1K2KeysForKey(key, KeyHelper.getCipherForK1K2TDEAGeneration(),
                        new byte[8], KeyHelper.getDerivationConstantForK1K2GenerationOfKey());
                break;
            case AES:
                subKeys = KeyHelper.generateCMACK1K2KeysForKey(key, KeyHelper.getCipherForK1K2AESGeneration(),
                        new byte[16], KeyHelper.getDerivationConstantForK1K2GenerationOfAESKey());
                break;
            default:
                throw new UnsupportedOperationException("Algorithm not supported: " + algo);
        }

        this.key = key;
    }

    public byte[] generate(byte[] message) throws Exception {
        switch (algo) {
            case TDES:
                return generateMAC("DESede/CBC/NoPadding", 8, 8, message);
            case AES:
                return generateMAC("AES/CBC/NoPadding", 16, 16, message);
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algo);
        }
    }

    private byte[] generateMAC(String transformation, int blocksize, int macSize, byte[] message)
            throws Exception {
        byte[] iv = new byte[blocksize];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Bytes lastBlock;
        Bytes data = Bytes.from(message);
        boolean emptyMessage = data.length() == 0;

        if (emptyMessage || data.length() % blocksize != 0) {
            int padLength = emptyMessage ? blocksize : blocksize - data.length() % blocksize;
            data = data.append((byte) 0x80);
            data = data.append(new byte[padLength - 1]);
            lastBlock = data.copy(data.length() - blocksize, blocksize);
            lastBlock = lastBlock.xor(subKeys.getValue1());// XOR with KM2
        } else {
            lastBlock = data.copy(data.length() - blocksize, blocksize);
            lastBlock = lastBlock.xor(subKeys.getValue0());// XOR with KM1
        }

        if (emptyMessage) {
            data = lastBlock;
        } else {
            // replace last block in padded data with the XOR'd last block
            data = data.resize(data.length() - blocksize, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_ZERO_INDEX)
                    .append(lastBlock);
        }

        Bytes result;
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            result = Bytes.from(cipher.doFinal(data.array()));
            // rightmost blocksize [16 or 8]
            return result.resize(macSize, BytesTransformer.ResizeTransformer.Mode.RESIZE_KEEP_FROM_MAX_LENGTH).array();
        }
        catch (Exception e) {
            throw new Exception(e);
        }
    }

}
