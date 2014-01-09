package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.DecryptionFailedException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.interfaces.RSAKey;

public abstract class RsaKey implements Key, RSAKey {

    public byte[] encrypt(byte[] input) {
        try {
            return doCrypto(input, Cipher.ENCRYPT_MODE);
        } catch (Exception e) {
            throw new IllegalStateException("Encrypting with an RSA key should always work. Using key="+this, e);
        }
    }

    public byte[] decrypt(byte[] input) throws DecryptionFailedException {
        try {
            return doCrypto(input, Cipher.DECRYPT_MODE);
        } catch (Exception e) {
            throw new DecryptionFailedException(e);
        }
    }

    private byte[] doCrypto(byte[] input, int encryptMode) throws Exception {
        Cipher rsa = RsaKeyUtils.cipher();
        try {
            rsa.init(encryptMode, this);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("An RSA Key should never be invalid for doing crypto. Using key="+this, e);
        }
        return rsa.doFinal(input);
    }
}
