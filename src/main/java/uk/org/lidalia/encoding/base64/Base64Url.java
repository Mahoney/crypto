package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.EncodedBase;

import java.util.regex.Pattern;

public class Base64Url extends EncodedBase<Base64Url> {

    private static final String validBase64Chars = "[a-zA-Z0-9/+]";
    private static final String lastFour = validBase64Chars+"{3}=|"+validBase64Chars+"{2}={2}|"+validBase64Chars+"={3}";
    static final Pattern legalBase64Encoding = Pattern.compile("("+validBase64Chars+"{4})*("+lastFour+")?");

    Base64Url(String encoded, Base64UrlEncoder encoder) throws NotABase64UrlEncodedString {
        super(encoded, encoder);
        if (!legalBase64Encoding.matcher(encoded).matches()) {
            throw NotABase64UrlEncodedString.of(encoded);
        }
    }

    @Override
    public Bytes decode() {
        return Bytes.of(java.util.Base64.getUrlDecoder().decode(toString()));
    }
}
