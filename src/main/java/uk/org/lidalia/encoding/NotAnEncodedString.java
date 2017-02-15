package uk.org.lidalia.encoding;

public abstract class NotAnEncodedString extends InvalidEncoding {

    private final String illegalString;

    protected NotAnEncodedString(String illegalString, String message, Throwable cause) {
        super(illegalString, message, cause);
        this.illegalString = illegalString;
    }

    @Override
    public String getInvalidEncoding() {
        return illegalString;
    }
}
