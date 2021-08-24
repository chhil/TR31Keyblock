package org.keyblock.tr31;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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
    public boolean                       wasPadded = false;
    private Bytes                        clearKeyPadding;

    public TR31KeyBlock(Header header) {
        this.header = header;
        // TODO Auto-generated constructor stub
    }

    public TR31KeyBlock() {
        // TODO Auto-generated constructor stub
    }

    public Cipher getCipherForK1K2TDEAGeneration() {
        try {
            return Cipher.getInstance("DESede/ECB/NoPadding");
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    public Cipher getCipherForK1K2AESGeneration() {
        try {
            return Cipher.getInstance("AES/ECB/NoPadding");
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    public void setCipherForK1K2GenerationForKBPF(Cipher cipherForK1K2GenerationForKBPF) {
    }

    public SecretKeySpec getKBPK() {
        return KBPK;
    }

    public String getEncodedHexStringKBPK() {
        return Bytes.from(KBPK.getEncoded())
                    .encodeHex(true);
    }

    public String getEncodedHexPrettyString(SecretKeySpec key) {
        if (key == null) {
            return null;
        }

        String str = Bytes.from(key.getEncoded())
                          .encodeHex(true);
        return str.replaceAll("................", "$0 ");// add space after every 16 characters

    }

    public byte[] getEncodedByteArrayKBPK() {
        return KBPK.getEncoded();
    }

    public void setKBPK(SecretKeySpec key) {
        if ("DESede".equals(key.getAlgorithm())) {
            // byte[] temp = Util.adjustDESParity(key.getEncoded());
            // SecretKeySpec spec = new SecretKeySpec(temp, key.getAlgorithm());
            KBPK = convertToTripleLengthKey(key);
        }

    }

    public Pair<Bytes, Bytes> getCMACKeyPairK1K2KBPK() {
        return cmacKeyPairK1K2KBPK;
    }

    public void setKeyPairCMACK1K2KBPK(Pair<Bytes, Bytes> keyPairK1K2KBPK) {
        this.cmacKeyPairK1K2KBPK = keyPairK1K2KBPK;
    }

    public SecretKeySpec getKBEK() {
        return KBEK;
    }

    public void setKBEK(SecretKeySpec KBEK) {
        if ("DESede".equals(KBEK.getAlgorithm())) {
            // byte[] temp = Util.adjustDESParity(key.getEncoded());
            // SecretKeySpec spec = new SecretKeySpec(temp, key.getAlgorithm());
            KBEK = convertToTripleLengthKey(KBEK);
        }
        this.KBEK = KBEK;
    }

    public Pair<Bytes, Bytes> getKeyPairK1K2KBEK() {
        return KeyPairK1K2KBEK;
    }

    public void setKeyPairK1K2KBEK(Pair<Bytes, Bytes> kbekPair) {
        this.KeyPairK1K2KBEK = kbekPair;
        Bytes tempKBEK = KeyPairK1K2KBEK.getValue0()
                                        .append(KeyPairK1K2KBEK.getValue1());
        try {
            setKBEK(new SecretKeySpec(tempKBEK.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public SecretKeySpec getKBMK() {
        return KBMKAuthenticationKey;
    }

    public void setKBMK(SecretKeySpec kkbmKeySpec) {
        if ("DESede".equals(kkbmKeySpec.getAlgorithm())) {
            // byte[] temp = Util.adjustDESParity(key.getEncoded());
            // SecretKeySpec spec = new SecretKeySpec(temp, key.getAlgorithm());
            KBMKAuthenticationKey = convertToTripleLengthKey(kkbmKeySpec);
        }
        else {
            KBMKAuthenticationKey = kkbmKeySpec;
        }

    }

    public Pair<Bytes, Bytes> getKeyPairK1K2KBMK() {
        return keyPairK1K2KBMK;
    }

    public void setKeyPairK1K2KBMK(Pair<Bytes, Bytes> keyPairK1K2KBMK) {
        this.keyPairK1K2KBMK = keyPairK1K2KBMK;

        Bytes tempKBMK = keyPairK1K2KBMK.getValue0()
                                        .append(keyPairK1K2KBMK.getValue1());
        try {
            setKBMK(new SecretKeySpec(tempKBMK.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    public static SecretKeySpec convertToTripleLengthKey(SecretKeySpec key) {

        if (key.getEncoded().length == 16) {
            // if its double length key
            // convert 128 bits key i.e. double length 3DES key to triple length 3DES 24 bit
            // key. K1 K2 K1
            byte[] tdesKey = new byte[24];
            System.arraycopy(key.getEncoded(), 0, tdesKey, 0, 16);// K1 K2 , 16 wide key = 8 bytes k1 + 8 bytes k2
            System.arraycopy(key.getEncoded(), 0, tdesKey, 16, 8); // K1 K2 K1, take the 8 bytes K1 and append it
            return new SecretKeySpec(tdesKey, key.getAlgorithm());
        }
        // its either single, triple or incorrect length
        return key;
    }

    /**
     * Used for K1 K2 generation of KBPK and KBMK
     *
     * @return
     */
    public String getDerivationConstantForK1K2GenerationOfKey() {
        return "000000000000001B";
    }

    public String getDerivationConstant1For2TDEAEncryptionForKBEK() {
        // 01 00 00 00 00 00 00 80
        //
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
    }

    public final String getDerivationConstant1For2TDEAAuthenticationForKBMK() {
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
    }

    public final String getDerivationConstant2For2TDEAAuthenticationForKBMK() {
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
    }

    public String getDerivationConstant2For2TDEAEncryptionForKBEK() {
        // 02 00 00 00 00 00 00 80
        //
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
    }

    public String getDerivationConstant1For3TDEAEncryptionForKBEK() {

        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
    }

    public String getDerivationConstant2For3TDEAEncryptionForKBEK() {

        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
    }

    public final String getDerivationConstant3For3TDEAEncryptionForKBEK() {

        return DerivationConstant._POS01_COUNTER._03 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
    }

    public final String getDerivationConstant1For3TDEAAuthenticationForKBMK() {
        // 01 00 01 00 00 00 00 80
        //
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
    }

    public final String get2TDEADerivationConstantForK1GenerationOfKBMK1() {
        // 01 00 01 00 00 00 00 80
        //
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
    }

    public final String get2TDEADerivationConstantForK2GenerationOfKBMK2() {
        // 02 00 01 00 00 00 00 80
        //
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0000_2TDEA
                + DerivationConstant._POS05_KEYLENGTH._0080_2TDEA;
    }

    public String getDerivationConstant2For3TDEAAuthenticationForKBMK() {

        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
    }

    public String getDerivationConstant3For3TDEAAuthenticationForKBMK() {

        return DerivationConstant._POS01_COUNTER._03 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0001_3TDEA
                + DerivationConstant._POS05_KEYLENGTH._00C0_3TDEA;
    }

    public void setKeyPairCMACKM1KM2KBMK(Pair<Bytes, Bytes> km1km2KBMK_CMAC) {
        this.cmacKeyPairKM1KM2KBMK = km1km2KBMK_CMAC;

        Bytes tempKBMKMACKey = cmacKeyPairKM1KM2KBMK.getValue0()
                                                    .append(cmacKeyPairKM1KM2KBMK.getValue1());
        try {
            setKBMK_MAC_Key(new SecretKeySpec(tempKBMKMACKey.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    public void setKBMK_MAC_Key(SecretKeySpec kbmk_cmac) {
        if ("DESede".equals(kbmk_cmac.getAlgorithm())) {
            // byte[] temp = Util.adjustDESParity(key.getEncoded());
            // SecretKeySpec spec = new SecretKeySpec(temp, key.getAlgorithm());
            KBMK_MAC_KEY = convertToTripleLengthKey(kbmk_cmac);
        }
        else {
            KBMK_MAC_KEY = kbmk_cmac;
        }

    }

    public SecretKeySpec getKBMK_MAC_Key() {
        return KBMK_MAC_KEY;
    }

    public Pair<Bytes, Bytes> getKeyPairCMACKM1KM2KBMK() {
        return cmacKeyPairKM1KM2KBMK;
    }

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }

    public Bytes getClearKey() {
        return clearKey;
    }

    public void setClearKey(Bytes clearKey) throws Exception {
        this.clearKey = clearKey;
        generateLengthEncodedClearKey();

    }

    public Bytes getlengthEncodedClearKey() {
        return lengthEncodedClearKey;
    }

    private void generateLengthEncodedClearKey() throws Exception {
        // Blocksize can be determined from the KBPK key size or the keyblock type. KBPK
        // may not be set before the clear key. Header is assumed to be set.
        if (header != null) {
            if (header.getKeyBlockType() == KeyblockType._D_AES_KEY_DERIVATION
                    || header.getKeyBlockType() == KeyblockType._1_THALES_AES) {
                BLOCKSIZE = 16;
            }
            else {
                BLOCKSIZE = 8;
            }
        }
        else if (getKBPK() != null) {
            if ("AES".equals(getKBPK().getAlgorithm())) {
                BLOCKSIZE = 16;
            }
            else {
                BLOCKSIZE = 8;
            }
        }
        int keyLengthBits = clearKey.length() * 8;
        Bytes encodedLength = Bytes.parseHex(Util.padleft(Integer.toHexString(keyLengthBits), 4, '0'));
        lengthEncodedClearKey = encodedLength.append(clearKey);
        lengthEncodedPaddedClearKey = lengthEncodedClearKey.copy();

        if (lengthEncodedPaddedClearKey.length() % BLOCKSIZE != 0) {

            // wasPadded = true;
            int padLength = BLOCKSIZE - (lengthEncodedClearKey.length() % BLOCKSIZE);
            Bytes arrayZeroes = Bytes.from(new byte[padLength]);
            // this creates a byte array initialized with 0x0
            // Fill it with random bytes. Note, this will result in a different MAC value
            // being generated eveytime even when the key is the same.

            new SecureRandom();

            lengthEncodedPaddedClearKey = lengthEncodedPaddedClearKey.append(arrayZeroes);
        }

    }

    public void generateMAC() throws Exception {

        switch (header.getKeyBlockType()) {
            case _0_THALES_DES:
                //$FALL-THROUGH$
            case _C_TDEA_KEY_VARIANT_BINDING:
                //$FALL-THROUGH$
            case _A_KEY_VARIANT_BINDING: {
                BLOCKSIZE = 8;
                setEncryptLengthEncodedPaddedKey();

                Bytes data = Bytes.from(getHeader().toString()
                                                   .getBytes())
                                  .append(getEncryptedKey());

                byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };

                SecretKeySpec secretKeySpec = getKBMK();

                Bytes result = null;
                try {
                    Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

                    result = Bytes.from(cipher.doFinal(data.array()));

                    setMessageMAC(result.copy(result.length() - 8, 4));// uses 4 byte mac
                }
                catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
                        | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                break;
            }
            case _B_TDEA_KEY_DERIVATION_BINDING: {
                BLOCKSIZE = 8;
                generateLengthEncodedClearKey();

                Bytes data = Bytes.from(getHeader().toString()
                                                   .getBytes())
                                  .append(getLengthEncodedPaddedClearKey());// doesn't take encrypted key
                if (data.length() % BLOCKSIZE != 0) {
                    int padLength = BLOCKSIZE - data.length() % BLOCKSIZE;
                    data = data.append((byte) 0x80);
                    data = data.append(new byte[padLength - 1]);

                }

                Bytes lastBlock = data.copy(data.length() - BLOCKSIZE, BLOCKSIZE);
                lastBlock = lastBlock.xor(getKeyPairCMACKM1KM2KBMK().getValue0());// XOR with KM1
                // replace last block in padded data with the KM1 xor block
                data = data.resize(data.length() - BLOCKSIZE, Mode.RESIZE_KEEP_FROM_ZERO_INDEX)
                           .append(lastBlock);
                byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0 };

                SecretKeySpec secretKeySpec = getKBMK();
                Bytes result = null;
                try {
                    Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

                    result = Bytes.from(cipher.doFinal(data.array()));

                    setMessageMAC(result.resize(8, Mode.RESIZE_KEEP_FROM_MAX_LENGTH));
                }
                catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
                        | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                setEncryptLengthEncodedPaddedKey();

                break;
            }

            case _1_THALES_AES: {

                BLOCKSIZE = 16;
                generateLengthEncodedClearKey();
                Bytes lastBlock = null;
                Bytes data = Bytes.from(getHeader().toString()
                                                   .getBytes())
                                  .append(getLengthEncodedPaddedClearKey());// doesn't take encrypted key
                if (data.length() % BLOCKSIZE != 0) {
                    int padLength = BLOCKSIZE - data.length() % BLOCKSIZE;
                    data = data.append((byte) 0x80);
                    data = data.append(new byte[padLength - 1]);
                    wasPadded = true;
                    lastBlock = data.copy(data.length() - BLOCKSIZE, BLOCKSIZE);
                    lastBlock = lastBlock.xor(getKeyPairCMACKM1KM2KBMK().getValue1());// XOR with KM2
                }
                else {
                    /*
                     * If you dont have optional headers, header is 16 and the key is already padded
                     * to BLOCKSIZE so you will always end up on this part of the else.
                     * That changes if you have optional blocks and changes the length to not be a
                     * multiple of the blocksize.
                     */
                    lastBlock = data.copy(data.length() - BLOCKSIZE, BLOCKSIZE);
                    lastBlock = lastBlock.xor(getKeyPairCMACKM1KM2KBMK().getValue0());// XOR with KM1
                }

                // replace last block in padded data with the XOR'd last block
                data = data.resize(data.length() - BLOCKSIZE, Mode.RESIZE_KEEP_FROM_ZERO_INDEX)
                           .append(lastBlock);
                byte[] iv = new byte[BLOCKSIZE];

                SecretKeySpec secretKeySpec = getKBMK();
                Bytes result = null;
                try {
                    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

                    result = Bytes.from(cipher.doFinal(data.array()));

                    setMessageMAC(result.resize(8, Mode.RESIZE_KEEP_FROM_MAX_LENGTH));// rightmost 16
                }
                catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
                        | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                setEncryptLengthEncodedPaddedKey();

                break;

            }

            case _D_AES_KEY_DERIVATION: {
                BLOCKSIZE = 16;
                generateLengthEncodedClearKey();
                Bytes lastBlock = null;
                Bytes data = Bytes.from(getHeader().toString()
                                                   .getBytes())
                                  .append(getLengthEncodedPaddedClearKey());// doesn't take encrypted key
                if (data.length() % BLOCKSIZE != 0) {
                    int padLength = BLOCKSIZE - data.length() % BLOCKSIZE;
                    data = data.append((byte) 0x80);
                    data = data.append(new byte[padLength - 1]);
                    wasPadded = true;
                    lastBlock = data.copy(data.length() - BLOCKSIZE, BLOCKSIZE);
                    lastBlock = lastBlock.xor(getKeyPairCMACKM1KM2KBMK().getValue1());// XOR with KM2
                }
                else {
                    /*
                     * If you dont have optional headers, header is 16 and the key is already padded
                     * to BLOCKSIZE so you will always end up on this part of the else.
                     * That changes if you have optional blocks and changes the length to not be a
                     * multiple of the blocksize.
                     */
                    lastBlock = data.copy(data.length() - BLOCKSIZE, BLOCKSIZE);
                    lastBlock = lastBlock.xor(getKeyPairCMACKM1KM2KBMK().getValue0());// XOR with KM1
                }

                // replace last block in padded data with the XOR'd last block
                data = data.resize(data.length() - BLOCKSIZE, Mode.RESIZE_KEEP_FROM_ZERO_INDEX)
                           .append(lastBlock);
                byte[] iv = new byte[BLOCKSIZE];

                SecretKeySpec secretKeySpec = getKBMK();
                Bytes result = null;
                try {
                    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

                    result = Bytes.from(cipher.doFinal(data.array()));

                    setMessageMAC(result.resize(16, Mode.RESIZE_KEEP_FROM_MAX_LENGTH));// rightmost 16
                }
                catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
                        | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                setEncryptLengthEncodedPaddedKey();

                break;

            }
            default:
                break;

        }

    }

    public void setMessageMAC(Bytes result) {
        this.MAC = result;
    }

    public Bytes getMessageMAC() {
        return this.MAC;
    }

    public Bytes getLengthEncodedPaddedClearKey() {
        return lengthEncodedPaddedClearKey;
    }

    public void setEncryptedKey(Bytes encryptedKey) {
        this.encryptedKey = encryptedKey;

    }

    public Bytes getEncryptedKey() {
        return this.encryptedKey;
    }

    public void setEncryptLengthEncodedPaddedKey() throws Exception {

        switch (header.getKeyBlockType()) {
            case _0_THALES_DES:
                //$FALL-THROUGH$
            case _C_TDEA_KEY_VARIANT_BINDING:
                //$FALL-THROUGH$
            case _A_KEY_VARIANT_BINDING: {
                String iv = header.toString()
                                  .substring(0, 8);// part of header used for MAC
                SecretKeySpec secretKeySpec = getKBEK();
                Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv.getBytes()));
                Bytes result = Bytes.from(cipher.doFinal(getLengthEncodedPaddedClearKey().array()));
                setEncryptedKey(result);
                break;
            }
            case _B_TDEA_KEY_DERIVATION_BINDING: {
                Bytes iv = getMessageMAC();// The MAC calculated is used as IV
                SecretKeySpec secretKeySpec = getKBEK();
                Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv.array()));
                Bytes result = Bytes.from(cipher.doFinal(getLengthEncodedPaddedClearKey().array()));
                setEncryptedKey(result);
                break;
            }

            case _1_THALES_AES: {
                String iv = header.toString()
                                  .substring(0, 16);
                SecretKeySpec secretKeySpec = getKBEK();
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv.getBytes()));
                Bytes result = Bytes.from(cipher.doFinal(getLengthEncodedPaddedClearKey().array()));
                setEncryptedKey(result);
                break;
            }

            case _D_AES_KEY_DERIVATION: {
                {
                Bytes iv = getMessageMAC();// The MAC calculated is used as IV
                SecretKeySpec secretKeySpec = getKBEK();
                Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv.array()));
                Bytes result = Bytes.from(cipher.doFinal(getLengthEncodedPaddedClearKey().array()));
                setEncryptedKey(result);
                break;
            }

            }
            default:
                break;

        }

    }

    public void setKBPK(String hexKBPK) {

        String algorithm = "";
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
                algorithm = "AES";
                break;
            default:
                break;

        }
        rawKBPK = Bytes.parseHex(hexKBPK.replace(" ", ""));

        SecretKeySpec spec = new SecretKeySpec(Bytes.parseHex(hexKBPK.replace(" ", ""))
                                                    .array(),
                                               algorithm);
        if ("DESede".equals(algorithm)) {
            // byte[] temp = Util.adjustDESParity(key.getEncoded());
            // SecretKeySpec spec = new SecretKeySpec(temp, key.getAlgorithm());
            KBPK = convertToTripleLengthKey(spec);
        }
        else {
            KBPK = spec;
        }

    }

    @Override
    public String toString() {
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
                    getClearKey().encodeHex(true), getlengthEncodedClearKey().encodeHex(true),
                    getLengthEncodedPaddedClearKey().encodeHex(true), getEncryptedKey().encodeHex(true));
            macString = String.format("Mac :%s%n", getMessageMAC().encodeHex(true));

            fullKeyBlockString = String.format("Header + encrypted key + mac%n%s %s %s", header,
                    getEncryptedKey().encodeHex(true), getMessageMAC().encodeHex(true));

            return kbpk + kbek + kbmk + kbmkmac + plainTextKey + macString + fullKeyBlockString;
        }
        catch (Exception e) {
            e.printStackTrace();
            return kbpk + kbek + kbmk + kbmkmac + plainTextKey + macString + fullKeyBlockString;

        }

    }

    public Bytes getRawKBPK() {
        return rawKBPK;
    }

    public void setRawKBPK(Bytes rawKBPK) {
        this.rawKBPK = rawKBPK;
    }

    public void generate() throws Exception {
        CMAC.deriveAllKeys(this);
        generateMAC();
    }

    public void setKeyTripletK1K2K3KBEK(Triplet<Bytes, Bytes, Bytes> triplet) {

        Bytes tempKBEK = triplet.getValue0()
                                .append(triplet.getValue1()
                                               .append(triplet.getValue2()));
        tripletK1K2K3KBEK = triplet;
        try {
            setKBEK(new SecretKeySpec(tempKBEK.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void setKeyTripletK1K2K3KBMK(Triplet<Bytes, Bytes, Bytes> triplet) {

        Bytes tempKBMK = triplet.getValue0()
                                .append(triplet.getValue1()
                                               .append(triplet.getValue2()));
        tripletK1K2K3KBMK = triplet;
        try {
            setKBMK(new SecretKeySpec(tempKBMK.array(), KBPK.getAlgorithm()));
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    public Triplet<Bytes, Bytes, Bytes> getTripletK1K2K3KBEK() {
        return tripletK1K2K3KBEK;
    }

    public Triplet<Bytes, Bytes, Bytes> getTripletK1K2K3KBMK() {
        return tripletK1K2K3KBMK;
    }

    public String getDerivationConstantForK1K2GenerationOfAESKey() {
        return "00000000000000000000000000000087";// used for KBPK and KBMK;
    }

    /**
     * @return
     *         A padded constant of 32 ASCII HEX (16 bytes), as hats the AES block
     *         size
     */
    public String getDerivationConstant1For256AESEncryptionForKBEK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;
    }

    public String getDerivationConstant2For256AESEncryptionForKBEK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;
    }

    /**
     * @return
     *         A padded constant of 32 ASCII HEX (16 bytes), as hats the AES block
     *         size. Constant is derived from key counter / algorithm / key size
     */
    public String get2AES256DerivationConstantForK1GenerationOfKBEK2() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;
    }

    public String get2AES128DerivationConstantForK2GenerationOfKBEK2() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0002_AES128
                + DerivationConstant._POS05_KEYLENGTH._0080_AES128 + padding;
    }

    public String getDerivationConstant1For128AESEncryptionForKBEK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0002_AES128
                + DerivationConstant._POS05_KEYLENGTH._0080_AES128 + padding;
    }

    public String getDerivationConstant1For128AESAuthenticationForKBMK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0002_AES128
                + DerivationConstant._POS05_KEYLENGTH._0080_AES128 + padding;
    }

    public String getDerivationConstant1For192AESEncryptionForKBEK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0003_AES192
                + DerivationConstant._POS05_KEYLENGTH._00C0_AES192 + padding;
    }

    public String getDerivationConstant1For192AESAuthenticationForKBMK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0003_AES192
                + DerivationConstant._POS05_KEYLENGTH._00C0_AES192 + padding;
    }

    public String getDerivationConstant2For192AESAuthenticationForKBMK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0003_AES192
                + DerivationConstant._POS05_KEYLENGTH._00C0_AES192 + padding;
    }

    public String getDerivationConstant2For192AESEncryptionForKBEK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0000_ENCRYPTION
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0003_AES192
                + DerivationConstant._POS05_KEYLENGTH._00C0_AES192 + padding;
    }

    public String getDerivationConstant1For256AESAuthenticationForKBMK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;
    }

    public String getDerivationConstant2For256AESAuthenticationForKBMK() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;
    }

    public String get2AES128DerivationConstantForK2GenerationOfKBMK2() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0002_AES128
                + DerivationConstant._POS05_KEYLENGTH._0080_AES128 + padding;
    }

    public String get1AES128DerivationConstantForK1GenerationOfKBMK1() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._01 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0002_AES128
                + DerivationConstant._POS05_KEYLENGTH._0080_AES128 + padding;
    }

    public String get2AES256DerivationConstantForK1GenerationOfKBMK2() {
        String padding = "8000000000000000"; // 16 wide
        return DerivationConstant._POS01_COUNTER._02 + DerivationConstant._POS02_KEYUSAGE._0001_MAC
                + DerivationConstant._POS03_00_SEPATATOR + DerivationConstant._POS04_ALGORITHM._0004_AES256
                + DerivationConstant._POS05_KEYLENGTH._0100_AES256 + padding;
    }

    /**
     * Takes in an Enrypted keyblock and KBPK.
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
     */
    public boolean decryptAndValidateEncryptedKeyblock(String keyBlock, String kbpk) throws Exception {
        //
        boolean valid = false;
        // Currently not handling optional headers so we know header is 16 wide
        header = new Header(keyBlock.substring(0, 16));
        TR31KeyBlock kb = new TR31KeyBlock(header);
        kb.setKBPK(kbpk);
        CMAC.deriveAllKeys(kb);
        if (header.getKeyBlockType() == KeyblockType._D_AES_KEY_DERIVATION) {
            valid = validateKeyblockTypeAES_D(keyBlock, kb);

        }
        if (header.getKeyBlockType() == KeyblockType._1_THALES_AES) {
            valid = validateKeyblockTypeThalesAES_1(keyBlock, kb);

        }
        return valid;

    }

    private boolean validateKeyblockTypeThalesAES_1(String keyBlock, TR31KeyBlock kb) throws Exception {
        boolean valid;
        Bytes tempMAC = Bytes.parseHex(keyBlock.substring(keyBlock.length() - 16));
        tempMAC = Bytes.parseHex("4E7921915A1438B8");
        System.out.println("MAC :" + tempMAC);
        String headerString = "10096P0TE00E0000".substring(0, 8);
        System.out.println("header :" + headerString);
        kb.setEncryptedKey(Bytes.parseHex(keyBlock.substring(16, keyBlock.length() - 16)));
        System.out.println("Encrypted Key : " + kb.getEncryptedKey()
                                                  .encodeHex(true));
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        // SecretKeySpec tempKeySpec = new SecretKeySpec(kb.getKBEK()
        // .getEncoded(),
        // "DESede");
        // tempKeySpec = convertToTripleLengthKey(tempKeySpec);
        Bytes iv = Bytes.from(headerString)
                        .append(tempMAC);
        // iv = Bytes.parseHex("00000000000000000000000000000000");
        // iv = Bytes.from(keyBlock.substring(0, 16));
        System.out.println("IV : " + iv.encodeHex(true));
        IvParameterSpec ivSpec = new IvParameterSpec(iv.array());
        cipher.init(Cipher.DECRYPT_MODE, kb.getKBEK(), ivSpec);
        Bytes result = Bytes.from(cipher.doFinal(kb.encryptedKey.array()));
        System.out.println("Decrypted Key :" + result.encodeHex(true));
        int keyBitsLength = Integer.parseInt(result.copy(0, 2) // length is hex ascii 4 hence 2 bytes
                                                   .encodeHex(true),
                16);

        kb.setClearKey(result.copy(2, keyBitsLength / 8));
        kb.setClearKeyPadding(result.copy(2 + keyBitsLength / 8, result.length() - (keyBitsLength / 8 + 2)));
        kb.generateMAC();

        System.out.println("Encrypted Keyblock :" + keyBlock);
        System.out.println("From Encrypted Keyblock - Header :" + header);

        System.out.println("From Encrypted Keyblock - Encrypted key :" + kb.getEncryptedKey()
                                                                           .encodeHex(true));

        System.out.println("From Encrypted Keyblock - Length Encoded and padded clearkey :" + result.encodeHex(true));
        System.out.println("From Encrypted Keyblock - clearkey :" + kb.getClearKey()
                                                                      .encodeHex(true));
        System.out.println("From Encrypted Keyblock - clearkey padding :" + kb.getClearKeyPadding()
                                                                              .encodeHex(true));
        if (!kb.getMessageMAC()
               .equals(tempMAC)) {

            System.out.println(
                    String.format("Encrypted Keyblock MAC received [%s] and MAC calculated [%s] are NOT EQUAL.",
                            tempMAC.encodeHex(true), kb.getMessageMAC()
                                                       .encodeHex(true)));
            valid = false;
        }
        else {
            System.out.println(String.format("Encrypted Keyblock MAC received [%s] and MAC calculated [%s] are EQUAL.",
                    tempMAC.encodeHex(true), kb.getMessageMAC()
                                               .encodeHex(true)));
            valid = true;
        }
        return valid;
    }

    protected boolean validateKeyblockTypeAES_D(String keyBlock, TR31KeyBlock kb)
            throws Exception {
        boolean valid;
        Bytes tempMAC = Bytes.parseHex(keyBlock.substring(keyBlock.length() - 32));
        kb.setEncryptedKey(Bytes.parseHex(keyBlock.substring(16, keyBlock.length() - 32)));
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, kb.getKBEK(), new IvParameterSpec(tempMAC.array()));
        Bytes result = Bytes.from(cipher.doFinal(kb.encryptedKey.array()));

        int keyBitsLength = Integer.parseInt(result.copy(0, 2) // length is hex ascii 4 hence 2 bytes
                                                   .encodeHex(true),
                16);

        kb.setClearKey(result.copy(2, keyBitsLength / 8));
        kb.setClearKeyPadding(result.copy(2 + keyBitsLength / 8, result.length() - (keyBitsLength / 8 + 2)));
        kb.generateMAC();

        System.out.println("Encrypted Keyblock :" + keyBlock);
        System.out.println("From Encrypted Keyblock - Header :" + header);

        System.out.println("From Encrypted Keyblock - Encrypted key :" + kb.getEncryptedKey()
                                                                           .encodeHex(true));

        System.out.println(
                "From Encrypted Keyblock - Length Encoded and padded clearkey :" + result.encodeHex(true));
        System.out.println("From Encrypted Keyblock - clearkey :" + kb.getClearKey()
                                                                      .encodeHex(true));
        System.out.println("From Encrypted Keyblock - clearkey padding :" + kb.getClearKeyPadding()
                                                                              .encodeHex(true));
        if (!kb.getMessageMAC()
               .equals(tempMAC)) {

            System.out.println(
                    String.format("Encrypted Keyblock MAC received [%s] and MAC calculated [%s] are NOT EQUAL.",
                            tempMAC.encodeHex(true), kb.getMessageMAC()
                                                       .encodeHex(true)));
            valid = false;
        }
        else {
            System.out.println(
                    String.format("Encrypted Keyblock MAC received [%s] and MAC calculated [%s] are EQUAL.",
                            tempMAC.encodeHex(true), kb.getMessageMAC()
                                                       .encodeHex(true)));
            valid = true;
        }
        return valid;
    }

    private void setClearKeyPadding(Bytes clearKeyPadding) {
        this.clearKeyPadding = clearKeyPadding;

    }

    public Bytes getClearKeyPadding() {
        return clearKeyPadding;
    }

}
