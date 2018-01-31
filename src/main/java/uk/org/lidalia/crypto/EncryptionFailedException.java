package uk.org.lidalia.crypto;

public class EncryptionFailedException extends Exception {
    public EncryptionFailedException(final Throwable cause) {
        super("Unable to encrypt data", cause);
    }
}
