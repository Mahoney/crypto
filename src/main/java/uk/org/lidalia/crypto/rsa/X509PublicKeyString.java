package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static uk.org.lidalia.crypto.rsa.X509PublicKeyEncoder.x509PublicKey;
import static uk.org.lidalia.crypto.rsa.X509PublicKeyStringEncoder.x509PublicKeyString;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class X509PublicKeyString
        extends CachedEncodedBase<RsaPublicKey, String, X509PublicKeyString>
        implements Encoded<RsaPublicKey, String, X509PublicKeyString> {

    X509PublicKeyString(String raw) throws InvalidEncoding {
        super(raw, doDecode(raw));
    }

    X509PublicKeyString(RsaPublicKey key) {
        super(doEncode(key), key);
    }

    private static String doEncode(RsaPublicKey decoded) {

        return "-----BEGIN PUBLIC KEY-----\n"+
                x509PublicKey.encode(decoded).raw().encode().toString().replaceAll("(.{64})", "$1\n")+
                "\n-----END PUBLIC KEY-----\n";
    }

    private static Pattern keyRegex = Pattern.compile(".*-----BEGIN PUBLIC KEY-----(?<base64Key>.*)-----END PUBLIC KEY-----.*", Pattern.DOTALL);

    private static RsaPublicKey doDecode(String raw) throws InvalidEncoding {

        Matcher keyMatcher = keyRegex.matcher(raw);

        if (keyMatcher.matches()) {

            String base64KeyStr = keyMatcher.group("base64Key").replaceAll("\\s+", "");
            Bytes keyBytes = base64.of(base64KeyStr).decode();
            return x509PublicKey.of(keyBytes).decode();
        } else {
            throw new InvalidEncoding(raw, "Unknown key format", null) {};
        }
    }

    @Override
    public X509PublicKeyStringEncoder encoder() {
        return x509PublicKeyString;
    }

}
