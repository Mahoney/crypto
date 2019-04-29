package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.bytes.NotAnEncodedString;

public class NotABase64UrlEncodedString extends NotAnEncodedString {

    public static NotABase64UrlEncodedString of(String illegalString) {
        return of(illegalString, null);
    }

    public static NotABase64UrlEncodedString of(String illegalString, Throwable t) {
        return new NotABase64UrlEncodedString(illegalString, illegalString+" is not base64 URL encoded", t);
    }

    private NotABase64UrlEncodedString(String illegalString, String message, Throwable cause) {
        super(illegalString, message, cause);
    }
}
