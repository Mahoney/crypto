package uk.org.lidalia.encoding;

public abstract class NotAnEncodedString extends Exception {

    private final String illegalString;

    protected NotAnEncodedString(String illegalString, String message, Throwable cause) {
        super(message, cause);
        this.illegalString = illegalString;
    }

    public String getIllegalString() {
        return illegalString;
    }
}
