package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.ComposedEncoder;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import static java.util.regex.Pattern.DOTALL;
import static java.util.regex.Pattern.compile;
import static uk.org.lidalia.crypto.rsa.Pkcs1Encoder.pkcs1;
import static uk.org.lidalia.crypto.rsa.Pkcs1StringEncoder.pkcs1String;

public class Pkcs1String extends CachedEncodedBase<RsaPrivateKey, String, Pkcs1String> implements Encoded<RsaPrivateKey, String, Pkcs1String> {

    private static final ComposedEncoder<RsaPrivateKey, Bytes, String> base64StringFormatEncoder = new ComposedEncoder<>(
            pkcs1,
            new Base64StringFormatEncoder(
                compile(
                        ".*-----BEGIN RSA PRIVATE KEY-----(?<base64Block>.*)-----END RSA PRIVATE KEY-----.*",
                        DOTALL
                )
            )
    );

    Pkcs1String(String raw) throws InvalidEncoding {
        super(raw, base64StringFormatEncoder.of(raw).decode());
    }

    @Override
    public Pkcs1StringEncoder encoder() {
        return pkcs1String;
    }

}
