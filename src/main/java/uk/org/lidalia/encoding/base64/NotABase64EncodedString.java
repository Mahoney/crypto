package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.NotAnEncodedString;

public class NotABase64EncodedString extends NotAnEncodedString {

    public static NotABase64EncodedString of(String illegalString) {
        return new NotABase64EncodedString(illegalString, illegalString+" is not base64 encoded; should match "+Base64.legalBase64Encoding);
    }

    private NotABase64EncodedString(String illegalString, String message) {
        super(illegalString, message, null);
    }
}
