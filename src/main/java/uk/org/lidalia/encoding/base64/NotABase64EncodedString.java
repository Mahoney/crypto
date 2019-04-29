package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.bytes.NotAnEncodedString;

public class NotABase64EncodedString extends NotAnEncodedString {

    public static NotABase64EncodedString of(String illegalString, Throwable t) {
        return new NotABase64EncodedString(illegalString, "Not a base64 encoded string: ["+illegalString+"]", t);
    }

    private NotABase64EncodedString(String illegalString, String message, Throwable t) {
        super(illegalString, message, t);
    }
}
