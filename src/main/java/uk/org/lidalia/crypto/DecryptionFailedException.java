package uk.org.lidalia.crypto;

public class DecryptionFailedException extends Exception {
    public DecryptionFailedException(final Throwable cause) {
        super("Unable to decrypt data", cause);
    }
}
