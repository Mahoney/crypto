package uk.org.lidalia.encoding.base64;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.EncodedBase;
import uk.org.lidalia.encoding.Encoder;

import java.util.regex.Pattern;

public class Base64 extends EncodedBase<Base64> {

    private static final String validBase64Chars = "[a-zA-Z0-9/+]";
    private static final String lastFour = validBase64Chars+"{3}=|"+validBase64Chars+"{2}={2}|"+validBase64Chars+"={3}";
    static final Pattern legalBase64Encoding = Pattern.compile("("+validBase64Chars+"{4})*("+lastFour+")?");

    Base64(String encoded, Encoder<Base64> encoder) throws NotABase64EncodedString {
        super(encoded, encoder);
        if (!legalBase64Encoding.matcher(encoded).matches()) {
            throw NotABase64EncodedString.of(encoded);
        }
    }

    @Override
    public Bytes decode() {
        return Bytes.of(java.util.Base64.getDecoder().decode(toString()));
    }
}
