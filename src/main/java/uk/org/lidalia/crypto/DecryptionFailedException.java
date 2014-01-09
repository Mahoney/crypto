package uk.org.lidalia.crypto;

public class DecryptionFailedException extends Exception {
    public DecryptionFailedException(Throwable cause) {
        super("Unable to decrypt data", cause);
    }
}
