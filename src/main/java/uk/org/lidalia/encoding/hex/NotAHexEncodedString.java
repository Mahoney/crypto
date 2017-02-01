package uk.org.lidalia.encoding.hex;

import uk.org.lidalia.encoding.NotAnEncodedString;

public class NotAHexEncodedString extends NotAnEncodedString {

    public static NotAHexEncodedString of(String illegalString) {
        return new NotAHexEncodedString(illegalString, illegalString+" is not hex encoded; should match "+Hex.legalHexEncoding);
    }

    private NotAHexEncodedString(String illegalString, String message) {
        super(illegalString, message, null);
    }
}
