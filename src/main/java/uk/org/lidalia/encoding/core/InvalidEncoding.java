package uk.org.lidalia.encoding.core;

public abstract class InvalidEncoding extends Exception {

    private final Object invalidEncoding;

    protected InvalidEncoding(Object invalidEncoding, String message, Throwable cause) {
        super(message, cause);
        this.invalidEncoding = invalidEncoding;
    }

    public Object getInvalidEncoding() {
        return invalidEncoding;
    }
}
