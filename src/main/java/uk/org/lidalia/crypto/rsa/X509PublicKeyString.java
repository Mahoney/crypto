package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.ComposedEncoder;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import static java.util.regex.Pattern.DOTALL;
import static java.util.regex.Pattern.compile;
import static uk.org.lidalia.crypto.rsa.X509PublicKeyEncoder.x509PublicKey;
import static uk.org.lidalia.crypto.rsa.X509PublicKeyStringEncoder.x509PublicKeyString;

public class X509PublicKeyString
        extends CachedEncodedBase<RsaPublicKey, String, X509PublicKeyString>
        implements Encoded<RsaPublicKey, String, X509PublicKeyString> {

    private static final ComposedEncoder<RsaPublicKey, Bytes, String> base64StringFormatEncoder = new ComposedEncoder<>(
            x509PublicKey,
            new Base64StringFormatEncoder(
                compile(
                        ".*-----BEGIN PUBLIC KEY-----(?<base64Block>.*)-----END PUBLIC KEY-----.*",
                        DOTALL
                )
            )
    );

    X509PublicKeyString(String raw) throws InvalidEncoding {
        super(raw, base64StringFormatEncoder.of(raw).decode());
    }

    X509PublicKeyString(RsaPublicKey key) {
        super(base64StringFormatEncoder.encode(key).raw(), key);
    }

    @Override
    public X509PublicKeyStringEncoder encoder() {
        return x509PublicKeyString;
    }

}
