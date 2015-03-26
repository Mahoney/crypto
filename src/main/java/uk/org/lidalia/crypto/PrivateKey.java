package uk.org.lidalia.crypto;

import uk.org.lidalia.crypto.rsa.Algorithm;

public interface PrivateKey<Public extends PublicKey<Public, Private>, Private extends PrivateKey<Public, Private>> extends java.security.PrivateKey, Key<Public, Private> {

    byte[] signatureFor(
        HashAlgorithm hashAlgorithm,
        byte[]... contents);

    byte[] decrypt(byte[] input) throws DecryptionFailedException;
}
