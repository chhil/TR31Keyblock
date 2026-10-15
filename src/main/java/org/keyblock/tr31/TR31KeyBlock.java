package org.keyblock.tr31;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.javatuples.Pair;
import org.javatuples.Triplet;
import org.keyblock.utils.Util;

import at.favre.lib.bytes.Bytes;
import at.favre.lib.bytes.BytesTransformer.ResizeTransformer.Mode;

public class TR31KeyBlock {

    protected int                        BLOCKSIZE = 8;
    protected SecretKeySpec              KBPK;
    protected Pair<Bytes, Bytes>         cmacKeyPairK1K2KBPK;
    protected SecretKeySpec              KBEK;
    protected Pair<Bytes, Bytes>         KeyPairK1K2KBEK;
    protected SecretKeySpec              KBMKAuthenticationKey;
    protected Pair<Bytes, Bytes>         keyPairK1K2KBMK;
    protected Header                     header;
    protected Bytes                      clearKey;

    private Pair<Bytes, Bytes>           cmacKeyPairKM1KM2KBMK;
    private SecretKeySpec                KBMK_MAC_KEY;
    private Bytes                        lengthEncodedClearKey;
    private Bytes                        lengthEncodedPaddedClearKey;
    private Bytes                        MAC;
    private Bytes                        encryptedKey;
    private Bytes                        rawKBPK;
    private Triplet<Bytes, Bytes, Bytes> tripletK1K2K3KBMK;
    private Triplet<Bytes, Bytes, Bytes> tripletK1K2K3KBEK;
    private Bytes                        clearKeyPadding;

    /**
     * Padding to use at the end of the clear key.
     * <p>
     * Deliberately zero filled so that key block generation is reproducible, which is what makes
     * the published example vectors comparable. ASC X9 TR 31-2018 5.3.2.1 asks for random padding
     * and X9.143 additionally requires padding out to the full key length so the length of the key
     * being transported is not disclosed. Anything that is not a test must call
     * {@link #setPaddingDataSource(PaddingDataSource)} with a
     * {@link SecureRandomPaddingDataSource} and call
     * {@link #enforceKeyLengthObfuscationPadding()}.
     */
    private PaddingDataSource            paddingDataSource = new ZeroPaddingDataSource();

    /**
     * Create a key block with the given header, usually followed by calls to
     * {@link #setKBPK(String)}, {@link #setClearKey(Bytes)}, optionally
     * {@link #setClearKeyPadding(Bytes)} and finally {@link #generate()}.
     * <p>
     * The header should not have the length populated, it will be populated during generation.
     *
     * @param header the header for this keyblock
     */
    public TR31KeyBlock(Header header) {
        this.header = header;
    }

    /**
     * Create an empty key block, usually followed by a call to
     * {@link #decryptKeyBlock(String, String)}.
     */
    public TR31KeyBlock() { }

    SecretKeySpec getKBPK() {
        return KBPK;
    }

    String getEncodedHexStringKBPK() {
        return Bytes.from(KBPK.getEncoded())
                    .encodeHex(true);
    }

    String getEncodedHexPrettyString(SecretKeySpec key) {
        if (key == null) {
            return null;
        }

        String str = Bytes.from(key.getEncoded())
                          .encodeHex(true);
        return str.replaceAll("................", "$0 ");// add space after every 16 characters
    }

    Pair<Bytes, Bytes> getCMACKeyPairK1K2KBPK() {
        return cmacKeyPairK1K2KBPK;
    }

    void setKeyPairCMACK1K2KBPK(Pair<Bytes, Bytes> keyPairK1K2KBPK) {
        this.cmacKeyPairK1K2KBPK = keyPairK1K2KBPK;
    }

    SecretKeySpec getKBEK() {
        return KBEK;
    }

    void setKBEK(SecretKeySpec KBEK) {
        if ("DESede".equals(KBEK.getAlgorithm())) {
            KBEK = KeyHelper.convertToTripleLengthKey(KBEK);
        }
        this.KBEK = KBEK;
    }

    Pair<Bytes, Bytes> getKeyPairK1K2KBEK() {
        return KeyPairK1K2KBEK;
    }

    void setKeyPairK1K2KBEK(Pair<Bytes, Bytes> kbekPair) {
        this.KeyPairK1K2KBEK = kbekPair;
        Bytes tempKBEK = KeyPairK1K2KBEK.getValue0()
                                        .append(KeyPairK1K2KBEK.getValue1());
        try {
            setKBEK(new SecretKeySpec(tempKBEK.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    SecretKeySpec getKBMK() {
        return KBMKAuthenticationKey;
    }

    void setKBMK(SecretKeySpec kkbmKeySpec) {
        if ("DESede".equals(kkbmKeySpec.getAlgorithm())) {
            KBMKAuthenticationKey = KeyHelper.convertToTripleLengthKey(kkbmKeySpec);
        }
        else {
            KBMKAuthenticationKey = kkbmKeySpec;
        }
    }

    Pair<Bytes, Bytes> getKeyPairK1K2KBMK() {
        return keyPairK1K2KBMK;
    }

    void setKeyPairK1K2KBMK(Pair<Bytes, Bytes> keyPairK1K2KBMK) {
        this.keyPairK1K2KBMK = keyPairK1K2KBMK;

        Bytes tempKBMK = keyPairK1K2KBMK.getValue0()
                                        .append(keyPairK1K2KBMK.getValue1());
        try {
            setKBMK(new SecretKeySpec(tempKBMK.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    Pair<String, String> getDerivationConstantPair2TDEAEncryptionForKBEK() {
        // 01 00 00 00 00 00 00 80
        //
        String constant1 = DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
        String constant2 = DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
        return new Pair<>(constant1, constant2);
    }

    Pair<String, String> getDerivationConstantPairFor2TDEAAuthenticationForKBMK() {
        String constant1 = DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
        String constant2 = DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
        return new Pair<>(constant1, constant2);
    }

    Triplet<String,String,String> getDerivationConstantTripletFor3TDEAEncryptionForKBEK() {

        String constant1 =  DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
        String constant2 =  DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
        String constant3 =  DerivationConstant._POS01_COUNTER._03 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;

        return new Triplet<>(constant1, constant2, constant3);
    }

    Triplet<String, String, String> getDerivationConstantTripletFor3TDEAAuthenticationForKBMK() {
        // 01 00 01 00 00 00 00 80
        //
        String constant1 = DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
        String constant2 = DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
        String constant3 = DerivationConstant._POS01_COUNTER._03 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
        return new Triplet<>(constant1, constant2, constant3);
    }

    void setKeyPairCMACKM1KM2KBMK(Pair<Bytes, Bytes> km1km2KBMK_CMAC) {
        this.cmacKeyPairKM1KM2KBMK = km1km2KBMK_CMAC;

        Bytes tempKBMKMACKey = cmacKeyPairKM1KM2KBMK.getValue0()
                                                    .append(cmacKeyPairKM1KM2KBMK.getValue1());
        try {
            setKBMK_MAC_Key(new SecretKeySpec(tempKBMKMACKey.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    void setKBMK_MAC_Key(SecretKeySpec kbmk_cmac) {
        if ("DESede".equals(kbmk_cmac.getAlgorithm())) {
            KBMK_MAC_KEY = KeyHelper.convertToTripleLengthKey(kbmk_cmac);
        }
        else {
            KBMK_MAC_KEY = kbmk_cmac;
        }
    }

    SecretKeySpec getKBMK_MAC_Key() {
        return KBMK_MAC_KEY;
    }

    Pair<Bytes, Bytes> getKeyPairCMACKM1KM2KBMK() {
        return cmacKeyPairKM1KM2KBMK;
    }

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
        invalidateLengthEncodedPaddedClearKey();
    }

    public Bytes getClearKey() {
        return clearKey;
    }

    public void setClearKey(Bytes clearKey) {
        this.clearKey = clearKey;
        invalidateLengthEncodedPaddedClearKey();
    }

    /**
     * The length encoded padded clear key is cached so that generation and MAC calculation see
     * identical bytes. Anything that changes an input to it has to drop the cache, otherwise a
     * second call to {@link #generate()} would silently reuse the previous padding.
     */
    private void invalidateLengthEncodedPaddedClearKey() {
        lengthEncodedClearKey = null;
        lengthEncodedPaddedClearKey = null;
    }

    public Bytes getLengthEncodedClearKey() {
        return lengthEncodedClearKey;
    }

    private boolean isAesEncrypted() {
        // Blocksize can be determined from the KBPK key size or the keyblock type. KBPK
        // may not be set before the clear key. Header is assumed to be set.
        if (header != null) {
            return header.getKeyBlockType().isAES();
        }
        else if (getKBPK() != null) {
            if ("AES".equals(getKBPK().getAlgorithm())) {
                return true;
            }
            else {
                return false;
            }
        }

        throw new UnsupportedOperationException();
    }

    /**
     * Key block format version E enciphers its confidential data with AES in CTR mode, which is a
     * stream cipher, so the data is not padded out to a multiple of the block size.
     */
    private boolean isStreamCipherEncrypted() {
        return header != null && header.getKeyBlockType() == KeyblockType._E_ISO20038_AES_KEY_DERIVATION;
    }

    private void generateLengthEncodedPaddedClearKey() {
        if (lengthEncodedPaddedClearKey != null) {
            return;
        }

        if (isAesEncrypted()) {
            BLOCKSIZE = 16;
        }
        else {
            BLOCKSIZE = 8;
        }

        KeyBlockValidation.validateKeyLength(header.getAlgorithm(), clearKey.length());

        int keyLengthBits = clearKey.length() * 8;
        Bytes encodedLength = Bytes.parseHex(Util.padLeft(Integer.toHexString(keyLengthBits), 4, '0'));
        lengthEncodedClearKey = encodedLength.append(clearKey);
        lengthEncodedPaddedClearKey = lengthEncodedClearKey.copy();

        // If padding is already supplied start with that, it may not be sufficient though
        if (clearKeyPadding != null) {
            lengthEncodedPaddedClearKey = lengthEncodedPaddedClearKey.append(clearKeyPadding);
        }

        if (!isStreamCipherEncrypted() && lengthEncodedPaddedClearKey.length() % BLOCKSIZE != 0) {
            // Additional padding is required to meet the block size requirement. A stream cipher
            // such as the AES-CTR of key block format version E preserves the length of its input,
            // so its confidential data is not rounded up to a multiple of the block size.
            int padLength = BLOCKSIZE - (lengthEncodedPaddedClearKey.length() % BLOCKSIZE);
            byte[] cipherBlockPadding = new byte[padLength];
            paddingDataSource.nextBytes(cipherBlockPadding);

            // Update the clear padding for record keeping
            if (this.clearKeyPadding == null) {
                clearKeyPadding = Bytes.from(cipherBlockPadding);
            } else {
                clearKeyPadding = clearKeyPadding.append(cipherBlockPadding);
            }

            lengthEncodedPaddedClearKey = lengthEncodedPaddedClearKey.append(cipherBlockPadding);
        }

        header.updateKeyBlockLength(lengthEncodedPaddedClearKey.length());
    }

    private int getMACLen() {
        return header.getKeyBlockType().getMACLen();
    }

    private boolean isEncryptThenMAC() {
        switch (header.getKeyBlockType()) {
            case _0_THALES_DES:
                //$FALL-THROUGH$
            case _1_THALES_AES:
                //$FALL-THROUGH$
            case _A_KEY_VARIANT_BINDING:
                //$FALL-THROUGH$
            case _C_TDEA_KEY_VARIANT_BINDING: {
                return true;
            }
            default: {
                // Sadly newer key block types use the less secure MAC-then-encrypt process
                return false;
            }
        }
    }

    /**
     * Decrypt, verify and populate the given key block using the key block protection key.
     * <p>
     * @param keyBlock The ASCII form is: header ASCII + confidential data hex + MAC hex
     * @param kbpkHex Key block protection key in hex
     */
    public void decryptKeyBlock(String keyBlock, String kbpkHex) throws Exception {
        decryptKeyBlock(keyBlock, kbpkHex, false);
    }

    /**
     * Unwrap a key block, optionally validating the data of each optional block against the
     * character format the standard requires for that optional block ID.
     * <p>
     * Strict validation is off by default. The example published in ANSI X9.143:2021 section 8.2
     * has a KS optional block whose data is not hexadecimal, and key blocks produced by HSMs are
     * known to do the same, so turning it on rejects some blocks that would otherwise unwrap.
     * Turn it on when the sender is not trusted and you would rather reject than accept a block
     * that does not comply.
     *
     * @param keyBlock
     *            the header ASCII + confidential data hex + MAC hex
     * @param kbpkHex
     *            the Key Block Protection Key in hex
     * @param strictOptionalBlockData
     *            true to validate optional block data, false to only validate structure
     */
    public void decryptKeyBlock(String keyBlock, String kbpkHex, boolean strictOptionalBlockData) throws Exception {
        header = new Header(keyBlock, strictOptionalBlockData);

        if (header.getKeyBlockLength() != keyBlock.length()) {
            // Either header is wrong or key block input is wrong
            String msg = String.format("Incorrect key block length (header specifies %d but given %d)",
                    header.getKeyBlockLength(), keyBlock.length());
            throw new IllegalArgumentException(msg);
        }

        setKBPK(kbpkHex);
        KeyHelper.deriveAllKeys(this);

        // 2 hex ASCII chars per byte
        final int numMacHexChars = getMACLen() * 2;
        final int headerLength = header.getLength();

        // Remove header and MAC to get encrypted key chunk
        encryptedKey = Bytes.parseHex(keyBlock.substring(headerLength, keyBlock.length() - numMacHexChars));

        // MAC is the last chunk of the raw key block
        final Bytes givenMAC = Bytes.parseHex(keyBlock.substring(keyBlock.length() - numMacHexChars));

        final byte[] iv;

        switch (header.getKeyBlockType()) {
            case _A_KEY_VARIANT_BINDING:
                //$FALL-THROUGH$
            case _0_THALES_DES:
                //$FALL-THROUGH$
            case _C_TDEA_KEY_VARIANT_BINDING: {
                String headerStr = header.toString();
                // IV is the first 8 chars (8 bytes) of the header
                iv = headerStr.substring(0, 8).getBytes(StandardCharsets.US_ASCII);
                break;
            }

            case _B_TDEA_KEY_DERIVATION_BINDING: {
                // IV is the first 8 bytes of the MAC
                iv = givenMAC.copy(0, 8).array();
                break;
            }

            case _E_ISO20038_AES_KEY_DERIVATION:
                //$FALL-THROUGH$
            case _D_AES_KEY_DERIVATION: {
                // IV is the first 16 bytes of the MAC
                iv = givenMAC.copy(0, 16).array();
                break;
            }

            case _1_THALES_AES: {
                // IV is the first 16 bytes of the header
                iv = header.toString()
                           .substring(0, 16)
                           .getBytes(StandardCharsets.US_ASCII);
                break;
            }

            default:
                // Every KeyblockType is handled above, so reaching here means a type has been added
                // without its IV rule. Fail loudly rather than guess.
                throw new UnsupportedOperationException("Cannot unwrap a key block of type "
                        + header.getKeyBlockType() + ", the IV it uses to decrypt is not defined");
        }

        decryptKeyBlock(iv);
        generateMAC();

        verifyMAC(givenMAC);
    }

    private void decryptKeyBlock(byte[] iv) throws Exception {
        String transformation;
        if (isStreamCipherEncrypted()) {
            // The MAC is the initial counter block for the AES-CTR of format version E
            transformation = "AES/CTR/NoPadding";
        }
        else if (isAesEncrypted()) {
            transformation = "AES/CBC/NoPadding";
        }
        else {
            transformation = "DESede/CBC/NoPadding";
        }

        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, getKBEK(), new IvParameterSpec(iv));
        Bytes result = Bytes.from(cipher.doFinal(encryptedKey.array()));

        extractLengthEncodedClearKey(result);

        generateLengthEncodedPaddedClearKey();
    }

    /**
     * The confidential data is the key length in bits followed by the key and any padding, see
     * ASC X9 TR 31-2018 A.7.2.2.3. The length is read from data that has only been decrypted and
     * not yet authenticated, so it must be validated before it is used to slice the result. A
     * wrong KBPK or a tampered key block produces a random length here.
     */
    private void extractLengthEncodedClearKey(Bytes lengthEncodedPaddedKey) {
        if (lengthEncodedPaddedKey.length() < 2) {
            throw new SecurityException("Confidential data is too short to contain a key length");
        }

        final int keyBitsLength = Integer.parseInt(lengthEncodedPaddedKey.copy(0, 2) // length is hex ascii 4 hence
                                                                                      // 2 bytes
                                                     .encodeHex(true), 16);

        if (keyBitsLength == 0 || keyBitsLength % 8 != 0) {
            throw new SecurityException("Invalid key length in confidential data: " + keyBitsLength);
        }

        final int keyLength = keyBitsLength / 8;

        if (keyLength > lengthEncodedPaddedKey.length() - 2) {
            throw new SecurityException("Key length " + keyBitsLength + " bits exceeds the confidential data ("
                    + ((lengthEncodedPaddedKey.length() - 2) * 8) + " bits available)");
        }

        setClearKeyPadding(lengthEncodedPaddedKey.copy(2 + keyLength, lengthEncodedPaddedKey.length()
                                                                        - (keyLength + 2)));
        setClearKey(lengthEncodedPaddedKey.copy(2, keyLength));
    }

    /**
     * The MAC comparison is deliberately not short circuiting so that it cannot be used to
     * recover the expected MAC one byte at a time.
     */
    private void verifyMAC(Bytes givenMAC) throws SecurityException {
        if (!MessageDigest.isEqual(givenMAC.array(), MAC.array())) {
            throw new SecurityException("MAC mismatch, given=" + givenMAC.encodeHex()
                    + ", computed=" + MAC.encodeHex());
        }
    }

    void generateMAC() {
        generateLengthEncodedPaddedClearKey();

        switch (header.getKeyBlockType()) {
            case _0_THALES_DES:
                //$FALL-THROUGH$
            case _C_TDEA_KEY_VARIANT_BINDING:
                //$FALL-THROUGH$
            case _A_KEY_VARIANT_BINDING: {
                BLOCKSIZE = 8;
                String transformation = "DESede/CBC/NoPadding";
                generateVariantMAC(transformation);
                break;
            }

            case _B_TDEA_KEY_DERIVATION_BINDING: {
                BLOCKSIZE = 8;
                String transformation = "DESede/CBC/NoPadding";
                generateDerivationMAC(transformation, BLOCKSIZE, 8);
                break;
            }

            case _1_THALES_AES: {
                BLOCKSIZE = 16;
                generateThalesAesMAC();
                break;
            }

            case _E_ISO20038_AES_KEY_DERIVATION:
                //$FALL-THROUGH$
            case _D_AES_KEY_DERIVATION: {
                BLOCKSIZE = 16;
                String transformation = "AES/CBC/NoPadding";
                generateDerivationMAC(transformation, BLOCKSIZE, 16);
                break;
            }

            default:
                throw new UnsupportedOperationException();
        }
    }

    /**
     * Thales key block type 1 derives its keys exactly as key block type D does, but protects the
     * block encrypt-then-MAC like the variant binding types: the MAC is an AES CMAC over the cleartext
     * header concatenated with the encrypted key, truncated to the 64 leftmost bits. The MAC is not a
     * prefix or suffix of the CMAC produced for type D.
     */
    private void generateThalesAesMAC() {
        Bytes data = Bytes.from(getHeader().toString()
                                        .getBytes(StandardCharsets.US_ASCII))
                          .append(getEncryptedKey());

        try {
            CMAC cmac = new CMAC(CMAC.Algorithm.AES, getKBMK()
                                                        .getEncoded());
            Bytes result = Bytes.from(cmac.generate(data.array()));
            setMessageMAC(result.resize(8, Mode.RESIZE_KEEP_FROM_ZERO_INDEX));// leftmost 64 bits
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void generateVariantMAC(String transformation) {
        Bytes data = Bytes.from(getHeader().toString().getBytes(StandardCharsets.US_ASCII))
                          .append(getEncryptedKey());

        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };

        SecretKeySpec secretKeySpec = getKBMK();

        Bytes result;
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
            result = Bytes.from(cipher.doFinal(data.array()));
            setMessageMAC(result.copy(result.length() - 8, 4));// uses 4 byte mac
        }
        catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Computes the CMAC over the cleartext header concatenated with the length encoded padded
     * clear key, see ASC X9 TR 31-2018 5.3.2.1.
     *
     * @param transformation
     *            the block cipher and mode in use, selects the CMAC algorithm
     * @param blocksize
     *            retained for source compatibility, the block size is taken from the CMAC algorithm
     * @param macSize
     *            the number of leading bytes of the rightmost block to keep as the MAC
     */
    protected void generateDerivationMAC(String transformation, int blocksize, int macSize) {
        // The MAC is taken over the cleartext header concatenated with the length encoded padded
        // clear key, it does not cover the encrypted key. See ASC X9 TR 31-2018 5.3.2.1.
        Bytes data = Bytes.from(getHeader().toString()
                                        .getBytes(StandardCharsets.US_ASCII))
                          .append(getLengthEncodedPaddedClearKey());

        try {
            // Deliberately delegating to CMAC rather than repeating it here, CMAC is the single
            // implementation and is covered by the NIST SP 800-38B test vectors.
            CMAC.Algorithm algo = transformation.startsWith("AES") ? CMAC.Algorithm.AES : CMAC.Algorithm.TDES;
            CMAC cmac = new CMAC(algo, getKBMK()
                                        .getEncoded());

            Bytes result = Bytes.from(cmac.generate(data.array()));
            setMessageMAC(result.resize(macSize, Mode.RESIZE_KEEP_FROM_MAX_LENGTH));// rightmost bytes [16 or 8]
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    void setMessageMAC(Bytes result) {
        this.MAC = result;
    }

    public Bytes getMessageMAC() {
        return this.MAC;
    }

    public Bytes getLengthEncodedPaddedClearKey() {
        return lengthEncodedPaddedClearKey;
    }

    void setEncryptedKey(Bytes encryptedKey) {
        this.encryptedKey = encryptedKey;
    }

    public Bytes getEncryptedKey() {
        return this.encryptedKey;
    }

    void encryptWithKBEK() throws Exception {
        switch (header.getKeyBlockType()) {
            case _0_THALES_DES:
                //$FALL-THROUGH$
            case _C_TDEA_KEY_VARIANT_BINDING:
                //$FALL-THROUGH$
            case _A_KEY_VARIANT_BINDING: {
                String transformation = "DESede/CBC/NoPadding";
                String iv = header.toString()
                                  .substring(0, 8);
                encryptWithKBEK(transformation, Bytes.from(iv));
                break;
            }

            case _B_TDEA_KEY_DERIVATION_BINDING: {
                String transformation = "DESede/CBC/NoPadding";
                Bytes iv = getMessageMAC();// The MAC calculated is used as IV
                encryptWithKBEK(transformation, iv);
                
                break;
            }

            case _1_THALES_AES: {
                String transformation = "AES/CBC/NoPadding";
                String iv = header.toString()
                                  .substring(0, 16);
                encryptWithKBEK(transformation, Bytes.from(iv));
                break;
            }

            case _E_ISO20038_AES_KEY_DERIVATION: {
                // ISO 20038:2017 uses AES in CTR mode, the MAC is the initial counter block
                encryptWithKBEK("AES/CTR/NoPadding", getMessageMAC());
                break;
            }

            case _D_AES_KEY_DERIVATION: {
                String transformation = "AES/CBC/NoPadding";
                Bytes iv = getMessageMAC();// The MAC calculated is used as IV
                encryptWithKBEK(transformation, iv);
                break;

            }

            default:
                throw new UnsupportedOperationException();
        }
    }

    protected void encryptWithKBEK(String transformation, Bytes iv)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKeySpec = getKBEK();
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv.array()));
        Bytes result = Bytes.from(cipher.doFinal(getLengthEncodedPaddedClearKey().array()));
        setEncryptedKey(result);
    }

    public void setKBPK(String hexKBPK) {
        String algorithm;
        switch (header.getKeyBlockType()) {
            //
            case _0_THALES_DES:
                //$FALL-THROUGH$
            case _A_KEY_VARIANT_BINDING:
                //$FALL-THROUGH$
            case _B_TDEA_KEY_DERIVATION_BINDING:
                // $FALL-THROUGH$
            case _C_TDEA_KEY_VARIANT_BINDING:
                algorithm = "DESede";
                break;
            case _1_THALES_AES:
                //$FALL-THROUGH$
            case _D_AES_KEY_DERIVATION:
                //$FALL-THROUGH$
            case _E_ISO20038_AES_KEY_DERIVATION:
                algorithm = "AES";
                break;
            default:
                throw new UnsupportedOperationException();
        }

        rawKBPK = Bytes.parseHex(hexKBPK.replace(" ", ""));

        SecretKeySpec spec = new SecretKeySpec(Bytes.parseHex(hexKBPK.replace(" ", ""))
                                                    .array(), algorithm);
        if ("DESede".equals(algorithm)) {
            KBPK = KeyHelper.convertToTripleLengthKey(spec);
        }
        else {
            KBPK = spec;
        }
    }

    @Override
    public String toString() {
        if (header == null || encryptedKey == null || MAC == null) {
            return "invalid";
        }

        return header +
                encryptedKey.encodeHex(true) +
                MAC.encodeHex(true);
    }

    public String toDebugString() {
        String kbpk = null, kbek = null, kbmk = null, kbmkmac = null, plainTextKey = null, macString = null,
                fullKeyBlockString = null;
        try {
            kbpk = String.format("KBPK %s%n  KBPK[K1_CMAC]=%s, KBPK[K2_CMAK]=%s%n", getRawKBPK().encodeHex(true)
                                                                                                .replaceAll(
                                                                                                        "................",
                                                                                                        "$0 "),
                    getCMACKeyPairK1K2KBPK() == null ? "not set"
                            : getCMACKeyPairK1K2KBPK().getValue0()
                                                      .encodeHex(true),
                    getCMACKeyPairK1K2KBPK() == null ? "not set"
                            : getCMACKeyPairK1K2KBPK().getValue1()
                                                      .encodeHex(true));
            if (getKeyPairK1K2KBEK() != null) {
                kbek = String.format("KBEK[kbek1]=%s KBEK[kbek2]=%s%nKBEK=%s%n",
                        getKeyPairK1K2KBEK().getValue0() == null ? "not set"
                                : getKeyPairK1K2KBEK().getValue0()
                                                      .encodeHex(true),
                        getKeyPairK1K2KBEK().getValue1() == null ? "not set"
                                : getKeyPairK1K2KBEK().getValue1()
                                                      .encodeHex(true),
                        getEncodedHexPrettyString(KBEK));
            }
            else if (getTripletK1K2K3KBEK() != null) {
                kbek = String.format("KBEK[kbek1]=%s KBEK[kbek2]=%s%n KBEK[kbek3]=%s%nKBEK=%s%n",
                        getTripletK1K2K3KBEK().getValue0() == null ? "not set"
                                : getTripletK1K2K3KBEK().getValue0()
                                                        .encodeHex(true),
                        getTripletK1K2K3KBEK().getValue1() == null ? "not set"
                                : getTripletK1K2K3KBEK().getValue1()
                                                        .encodeHex(true),
                        getTripletK1K2K3KBEK().getValue2() == null ? "not set"
                                : getTripletK1K2K3KBEK().getValue2()
                                                        .encodeHex(true),
                        getEncodedHexPrettyString(KBEK));

            }
            else {
                kbek = "not set";
            }

            if ((getKeyPairK1K2KBMK() != null)) {
                kbmk = String.format("KBMK[kbmk1]=%s KBMK[kbmk2]=%s%nKBMK=%s%n",
                        getKeyPairK1K2KBMK().getValue0() == null ? "not set"
                                : getKeyPairK1K2KBMK().getValue0()
                                                      .encodeHex(true),
                        getKeyPairK1K2KBMK().getValue1() == null ? "not set"
                                : getKeyPairK1K2KBMK().getValue1()
                                                      .encodeHex(true),
                        getEncodedHexPrettyString(KBMKAuthenticationKey));
            }
            else if ((getTripletK1K2K3KBMK() != null)) {
                kbmk = String.format("KBMK[kbmk1]=%s KBMK[kbmk2]=%s%n KBMK[kbmk2]=%s%nKBMK=%s%n",
                        getTripletK1K2K3KBMK().getValue0() == null ? "not set"
                                : getTripletK1K2K3KBMK().getValue0()
                                                        .encodeHex(true),
                        getTripletK1K2K3KBMK().getValue1() == null ? "not set"
                                : getTripletK1K2K3KBMK().getValue1()
                                                        .encodeHex(true),
                        getTripletK1K2K3KBMK().getValue2() == null ? "not set"
                                : getTripletK1K2K3KBMK().getValue2()
                                                        .encodeHex(true),
                        getEncodedHexPrettyString(KBMKAuthenticationKey));
            }
            else {
                kbmk = "not set";
            }
            kbmkmac = String.format("KBMK[KM1_CMAC]=%s KBMK[KM2_CMAC]=%s%nKBMK MAC Key=%s%n",
                    getKeyPairCMACKM1KM2KBMK() == null ? "not set"
                            : getKeyPairCMACKM1KM2KBMK().getValue0()
                                                        .encodeHex(true),
                    getKeyPairCMACKM1KM2KBMK() == null ? "not set"
                            : getKeyPairCMACKM1KM2KBMK().getValue1()
                                                        .encodeHex(true),
                    getEncodedHexPrettyString(getKBMK_MAC_Key()));

            plainTextKey = String.format(
                    "ClearKey=%s%n Length Encoded ClearKey=%s%n LengthEncode Padded Clear Key=%s%nEncrypted Key=%s%n",
                    getClearKey().encodeHex(true), getLengthEncodedClearKey().encodeHex(true),
                    getLengthEncodedPaddedClearKey().encodeHex(true), getEncryptedKey().encodeHex(true));
            macString = String.format("Mac :%s%n", getMessageMAC().encodeHex(true));

            fullKeyBlockString = String.format("Header + encrypted key + mac%n%s %s %s", header,
                    getEncryptedKey().encodeHex(true), getMessageMAC().encodeHex(true));

            return kbpk + kbek + kbmk + kbmkmac + plainTextKey + macString + fullKeyBlockString;
        }
        catch (Exception e) {
            return kbpk + kbek + kbmk + kbmkmac + plainTextKey + macString + fullKeyBlockString;
        }
    }

    Bytes getRawKBPK() {
        return rawKBPK;
    }

    /**
     * Generate a complete keyblock by encrypting the clear text key and creating the MAC.
     */
    public void generate() throws Exception {
        KeyHelper.deriveAllKeys(this);

        generateLengthEncodedPaddedClearKey();

        if (isEncryptThenMAC()) {
            encryptWithKBEK();
            generateMAC();
        } else {
            generateMAC();
            encryptWithKBEK();
        }
    }

    void setKeyTripletK1K2K3KBEK(Triplet<Bytes, Bytes, Bytes> triplet) {
        Bytes tempKBEK = triplet.getValue0()
                                .append(triplet.getValue1()
                                               .append(triplet.getValue2()));
        tripletK1K2K3KBEK = triplet;
        try {
            setKBEK(new SecretKeySpec(tempKBEK.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    void setKeyTripletK1K2K3KBMK(Triplet<Bytes, Bytes, Bytes> triplet) {
        Bytes tempKBMK = triplet.getValue0()
                                .append(triplet.getValue1()
                                               .append(triplet.getValue2()));
        tripletK1K2K3KBMK = triplet;
        try {
            setKBMK(new SecretKeySpec(tempKBMK.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    Triplet<Bytes, Bytes, Bytes> getTripletK1K2K3KBEK() {
        return tripletK1K2K3KBEK;
    }

    Triplet<Bytes, Bytes, Bytes> getTripletK1K2K3KBMK() {
        return tripletK1K2K3KBMK;
    }

    /**
     * Key usage indicator to use when deriving the Key Block Encryption Key. Key block format
     * version D derives in CBC mode (0x0000), version E derives in CTR mode (0x0002).
     */
    String encryptionKeyUsageIndicator() {
        return header.getKeyBlockType() == KeyblockType._E_ISO20038_AES_KEY_DERIVATION
                ? DerivationConstant._POS02_KEYUSAGE._0002_ENCRYPTION_CTR
                : DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION;
    }

    /**
     * @return
     *         A padded constant of 32 ASCII HEX (16 bytes), as hats the AES block
     *         size
     */
    Pair<String, String> getDerivationConstantPairFor256AESEncryptionForKBEK() {
        String padding = "8000000000000000"; // 16 wide
        String keyUsage = encryptionKeyUsageIndicator();
        String constant1 = DerivationConstant._POS01_COUNTER._01 + keyUsage
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;
        String constant2 = DerivationConstant._POS01_COUNTER._02 + keyUsage
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;
        return new Pair<>(constant1, constant2);
    }

    Pair<String, String> getDerivationConstantPairFor128AESEncryptionForKBEK() {
        String padding = "8000000000000000"; // 16 wide
        String keyUsage = encryptionKeyUsageIndicator();
        String constant1 = DerivationConstant._POS01_COUNTER._01 + keyUsage
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0002_AES128
                + DerivationConstant._POS05_KEYLENGTH._0080_AES128 + padding;
        String constant2 = DerivationConstant._POS01_COUNTER._02 + keyUsage
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0002_AES128
                + DerivationConstant._POS05_KEYLENGTH._0080_AES128 + padding;
        return new Pair<>(constant1, constant2);

    }

    Pair<String,String> getDerivationConstantPairFor128AESAuthenticationForKBMK() {
        String padding = "8000000000000000"; // 16 wide
        String constant1= DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0002_AES128
                + DerivationConstant._POS05_KEYLENGTH._0080_AES128 + padding;
        String constant2= DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0002_AES128
                + DerivationConstant._POS05_KEYLENGTH._0080_AES128 + padding;
        return new Pair<>(constant1, constant2);
    }

    Pair<String, String> getDerivationConstantPairFor192AESEncryptionForKBEK() {
        String padding = "8000000000000000"; // 16 wide
        String keyUsage = encryptionKeyUsageIndicator();
        String constant1 = DerivationConstant._POS01_COUNTER._01 + keyUsage
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0003_AES192
                + DerivationConstant._POS05_KEYLENGTH._00C0_AES192 + padding;
        String constant2 = DerivationConstant._POS01_COUNTER._02 + keyUsage
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0003_AES192
                + DerivationConstant._POS05_KEYLENGTH._00C0_AES192 + padding;
        return new Pair<>(constant1, constant2);

    }

    Pair<String, String> getDerivationConstantPairFor192AESAuthenticationForKBMK() {
        String padding = "8000000000000000"; // 16 wide
        String constant1 = DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0003_AES192
                + DerivationConstant._POS05_KEYLENGTH._00C0_AES192 + padding;
        String constant2 = DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0003_AES192
                + DerivationConstant._POS05_KEYLENGTH._00C0_AES192 + padding;
        return new Pair<>(constant1, constant2);

    }

    Pair<String, String> getDerivationConstantPairFor256AESAuthenticationForKBMK() {
        String padding = "8000000000000000"; // 16 wide
        String constant1 = DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;
        String constant2 = DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;

        return new Pair<>(constant1, constant2);
    }

    /**
     * Takes in an Encrypted keyblock and KBPK.
     * Extracts the header from it.
     * Drives all keys from the KBPK
     * Extracts encrypted key with length header.
     * Extracts clear key with length header and padding.
     * Calculates MAC using the extracted elements and compares it to the MAC
     * received in the encrypted keyblock
     *
     * @param keyBlock
     * @param kbpk
     * @return
     * @throws Exception
     *
     * @deprecated Use {@link #decryptKeyBlock(String, String)} instead.
     */
    @Deprecated
    public boolean decryptAndValidateEncryptedKeyblock(String keyBlock, String kbpk) throws Exception {
        boolean valid = false;
        header = new Header(keyBlock);
        setKBPK(kbpk);
        KeyHelper.deriveAllKeys(this);

        if (header.getKeyBlockType() == KeyblockType._D_AES_KEY_DERIVATION) {
            valid = validateKeyblockTypeAES_D(keyBlock);
        }
        if (header.getKeyBlockType() == KeyblockType._1_THALES_AES) {
            valid = validateKeyblockTypeThalesAES_1(keyBlock);
        }
        return valid;
    }

    private boolean validateKeyblockTypeThalesAES_1(String keyBlock) throws Exception {
        boolean valid;
        // 2 hex ASCII characters per byte, the Thales type 1 MAC is 8 bytes
        final int numMacHexChars = getMACLen() * 2;

        System.out.println("Encrypted KeyBlock :" + keyBlock);
        Bytes tempMAC = Bytes.parseHex(keyBlock.substring(keyBlock.length() - numMacHexChars));
        System.out.println("From Encrypted Keyblock - MAC :" + tempMAC.encodeHex(true));

        header = new Header(keyBlock);
        String headerString = header.toString();
        System.out.println("From Encrypted Keyblock - header :" + headerString);

        setEncryptedKey(Bytes.parseHex(keyBlock.substring(headerString.length(), keyBlock.length()
                - numMacHexChars)));
        System.out.println("From Encrypted Keyblock - Encrypted Key : " + getEncryptedKey().encodeHex(true));
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        Bytes iv = Bytes.from(headerString);
        System.out.println("IV : " + iv.encodeHex(true));
        IvParameterSpec ivSpec = new IvParameterSpec(iv.array());
        cipher.init(Cipher.DECRYPT_MODE, getKBEK(), ivSpec);
        Bytes result = Bytes.from(cipher.doFinal(encryptedKey.array()));
        System.out.println("Decrypted Length Encode Padded ClearKey  :" + result.encodeHex(true));
        int keyBitsLength = Integer.parseInt(result.copy(0, 2) // length is hex ascii 4 hence 2 bytes
                                                   .encodeHex(true),
                16);

        setClearKeyPadding(result.copy(2 + keyBitsLength / 8, result.length() - (keyBitsLength / 8 + 2)));// needs to
                                                                                                          // be done
                                                                                                          // before
                                                                                                          // seting
                                                                                                          // clear
                                                                                                          // key
        setClearKey(result.copy(2, keyBitsLength / 8));

        generateMAC();

        System.out.println("Encrypted Keyblock :" + keyBlock);
        System.out.println("Code generated - Encrypted key :" + getEncryptedKey().encodeHex(true));
        System.out.println("From Encrypted Keyblock - Length Encoded and padded clearkey :" + result.encodeHex(true));
        System.out.println("From Encrypted Keyblock - clearkey :" + getClearKey().encodeHex(true));
        System.out.println("From Encrypted Keyblock - clearkey padding :" + getClearKeyPadding().encodeHex(true));

        if (!getMessageMAC().equals(tempMAC)) {
            System.out.println(
                    String.format("Encrypted Keyblock MAC received [%s] and MAC calculated [%s] are NOT EQUAL.",
                            tempMAC.encodeHex(true), getMessageMAC().encodeHex(true)));
            valid = false;
        }
        else {
            System.out.println(String.format("Encrypted Keyblock MAC received [%s] and MAC calculated [%s] are EQUAL.",
                    tempMAC.encodeHex(true), getMessageMAC().encodeHex(true)));
            valid = true;
        }
        return valid;
    }

    protected boolean validateKeyblockTypeAES_D(String keyBlock) throws Exception {
        boolean valid;

        header = new Header(keyBlock);
        String headerString = header.toString();
        System.out.println("From Encrypted Keyblock - header :" + headerString);

        Bytes tempMAC = Bytes.parseHex(keyBlock.substring(keyBlock.length() - 32));
        setEncryptedKey(Bytes.parseHex(keyBlock.substring(headerString.length(), keyBlock.length() - 32)));
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, getKBEK(), new IvParameterSpec(tempMAC.array()));
        Bytes result = Bytes.from(cipher.doFinal(encryptedKey.array()));

        int keyBitsLength = Integer.parseInt(result.copy(0, 2) // length is hex ascii 4 hence 2 bytes
                                                   .encodeHex(true),
                16);

        setClearKey(result.copy(2, keyBitsLength / 8));
        setClearKeyPadding(result.copy(2 + keyBitsLength / 8, result.length() - (keyBitsLength / 8 + 2)));
        generateMAC();

        System.out.println("Encrypted Keyblock :" + keyBlock);
        System.out.println("From Encrypted Keyblock - Header :" + header);

        System.out.println("From Encrypted Keyblock - Encrypted key :" + getEncryptedKey().encodeHex(true));

        System.out.println("From Encrypted Keyblock - Length Encoded and padded clearkey :" + result.encodeHex(true));
        System.out.println("From Encrypted Keyblock - clearkey :" + getClearKey().encodeHex(true));
        System.out.println("From Encrypted Keyblock - clearkey padding :" + getClearKeyPadding().encodeHex(true));
        if (!getMessageMAC().equals(tempMAC)) {

            System.out.println(
                    String.format("Encrypted Keyblock MAC received [%s] and MAC calculated [%s] are NOT EQUAL.",
                            tempMAC.encodeHex(true), getMessageMAC().encodeHex(true)));
            valid = false;
        }
        else {
            System.out.println(String.format("Encrypted Keyblock MAC received [%s] and MAC calculated [%s] are EQUAL.",
                    tempMAC.encodeHex(true), getMessageMAC().encodeHex(true)));
            valid = true;
        }
        return valid;
    }

    /**
     * Padding to use at the end of the clear key. If the padding is not set and the clear key is
     * not a multiple of the block length then additional padding will be obtained using the
     * padding data source.
     */
    public void setClearKeyPadding(Bytes clearKeyPadding) {
        this.clearKeyPadding = clearKeyPadding;
        invalidateLengthEncodedPaddedClearKey();
    }

    /**
     * Number of bytes to use at the end of the clear key. If the number of bytes does not
     * result in a multiple of the block size then more padding will be added at the time
     * the key block is generated using the padding data source.
     */
    public void setClearKeyPadding(int numBytes) {
        if (numBytes == 0) {
            return;
        }

        if (numBytes < 0) {
            throw new IllegalArgumentException("Negative number of padding bytes not allowed");
        }

        byte[] padding = new byte[numBytes];
        paddingDataSource.nextBytes(padding);
        this.clearKeyPadding = Bytes.from(padding);
        invalidateLengthEncodedPaddedClearKey();
    }

    public Bytes getClearKeyPadding() {
        return clearKeyPadding;
    }

    /**
     * Set the padding data source for the generated key block, the default is zero byte padding
     * which is not secure but useful for testing.
     */
    public void setPaddingDataSource(PaddingDataSource pds) {
        this.paddingDataSource = pds;
    }

    /**
     * X9.143 (successor to TR-31) mandate when the confidential data is an AES or TDEA key:
     * <i>
     * TDEA and AES symmetric keys SHALL be padded with random key length obfuscation padding to
     * the maximum length for the algorithm, 192 bits for TDEA or 256 bits for AES.
     * </i>
     */
    public void enforceKeyLengthObfuscationPadding() {
        int keyLen = clearKey.length();
        int keyLenObfuscationPaddingLen = 0;

        switch (header.getAlgorithm()) {
            case _A_AES: {
                if (keyLen != (128 / 8) && keyLen != (192 / 8) && keyLen != (256 / 8)) {
                    throw new IllegalStateException("Illegal confidential AES key size");
                }
                keyLenObfuscationPaddingLen = (256 / 8) - keyLen;
            }
            break;
            case _T_TRIPLE_DES: {
                if (keyLen != (128 / 8) && keyLen != (192 / 8)) {
                    throw new IllegalStateException("Illegal confidential TDES key size");
                }
                keyLenObfuscationPaddingLen = (192 / 8) - keyLen;
            }
            break;
            default:
                // Silently leaving the padding empty would emit a key block that discloses the
                // length of the key it carries, which is the one thing this method exists to
                // prevent. Refuse rather than produce a block that looks protected and is not.
                throw new IllegalStateException("Key length obfuscation padding is not defined for algorithm "
                        + header.getAlgorithm()
                        + ", only AES and TDEA keys are padded out to their maximum length");
        }

        setClearKeyPadding(keyLenObfuscationPaddingLen);
    }
}
