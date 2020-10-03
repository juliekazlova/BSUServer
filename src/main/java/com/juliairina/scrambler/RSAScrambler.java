package com.juliairina.scrambler;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

public class RSAScrambler {

    private PublicKey publicKey;
    private Cipher encryptCipher;

    public RSAScrambler(byte[] encodedKey) throws GeneralSecurityException {
        encryptCipher = Cipher.getInstance("RSA");
        publicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(encodedKey));
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
    }

    public byte[] encrypt(byte[] data)
            throws GeneralSecurityException {
        return encryptCipher.doFinal(data);
    }
}
