package uk.org.lidalia.crypto.core;

public class DecryptionFailedException extends Exception {
    public DecryptionFailedException(final Throwable cause) {
        super("Unable to decrypt data", cause);
    }
}
