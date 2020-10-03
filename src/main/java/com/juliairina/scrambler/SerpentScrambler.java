package com.juliairina.scrambler;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;

public class SerpentScrambler {

    private byte[] iv;
    private SecretKey key;
    private KeyGenerator keyGenerator;
    private Cipher encryptCipher;
    private Cipher decryptCipher;

    public SerpentScrambler() throws GeneralSecurityException {
        keyGenerator = KeyGenerator.getInstance("Serpent", "BC");
        keyGenerator.init(256);

        key = generateKey();
    }

    public SecretKey generateKey() throws GeneralSecurityException {
        SecretKey key = keyGenerator.generateKey();

        encryptCipher = Cipher.getInstance("Serpent/CFB/NoPadding", "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);

        iv = encryptCipher.getIV();

        decryptCipher = Cipher.getInstance("Serpent/CFB/NoPadding", "BC");
        decryptCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return key;
    }

    public byte[] encrypt(byte[] data)
            throws GeneralSecurityException {
        return encryptCipher.doFinal(data);
    }

    public byte[] decrypt(byte[] cipherText)
            throws GeneralSecurityException {
        return decryptCipher.doFinal(cipherText);
    }

    public byte[] getIv() {
        return iv;
    }

    public SecretKey getKey() {
        return key;
    }

    public KeyGenerator getKeyGenerator() {
        return keyGenerator;
    }

    public Cipher getEncryptCipher() {
        return encryptCipher;
    }

    public Cipher getDecryptCipher() {
        return decryptCipher;
    }
}
