package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.NotAnEncodedString;

public class NotABase64UrlEncodedString extends NotAnEncodedString {

    public static NotABase64UrlEncodedString of(String illegalString) {
        return new NotABase64UrlEncodedString(illegalString, illegalString+" is not base64 URL encoded; should match "+Base64Url.legalBase64Encoding, null);
    }

    private NotABase64UrlEncodedString(String illegalString, String message, Throwable cause) {
        super(illegalString, message, cause);
    }
}
