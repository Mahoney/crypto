package uk.org.lidalia.crypto;

public interface PublicKey<Public extends PublicKey<Public, Private>, Private extends PrivateKey<Public, Private>> extends java.security.PublicKey, Key<Public, Private> {

    boolean verifySignature(
            byte[] signature,
            HashAlgorithm hashAlgorithm,
            byte[]... signedContents);

    byte[] encrypt(byte[] input);
}
