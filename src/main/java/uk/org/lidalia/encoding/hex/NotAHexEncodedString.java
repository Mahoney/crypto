package uk.org.lidalia.encoding.hex;

import uk.org.lidalia.encoding.core.NotAnEncodedString;

public class NotAHexEncodedString extends NotAnEncodedString {

    public static NotAHexEncodedString of(String illegalString) {
        return new NotAHexEncodedString(illegalString, "Not a hex encoded string: ["+illegalString+"]");
    }

    private NotAHexEncodedString(String illegalString, String message) {
        super(illegalString, message, null);
    }
}
