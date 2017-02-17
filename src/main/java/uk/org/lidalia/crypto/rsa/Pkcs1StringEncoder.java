package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.ComposedEncoder;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import static java.util.regex.Pattern.DOTALL;
import static java.util.regex.Pattern.compile;
import static uk.org.lidalia.crypto.rsa.Pkcs1Encoder.pkcs1;

public class Pkcs1StringEncoder implements Encoder<RsaPrivateKey, String, Pkcs1String> {

    public static final Pkcs1StringEncoder pkcs1String = new Pkcs1StringEncoder();

    private static final ComposedEncoder<RsaPrivateKey, Bytes, String> delegate = new ComposedEncoder<>(
            pkcs1,
            new Base64StringFormatEncoder(
                    compile(
                            ".*-----BEGIN RSA PRIVATE KEY-----(?<base64Block>.*)-----END RSA PRIVATE KEY-----.*",
                            DOTALL
                    )
            )
    );

    private Pkcs1StringEncoder() {}

    @Override
    public Pkcs1String of(String encodedKey) throws InvalidEncoding {
        return new Pkcs1String(encodedKey, delegate.of(encodedKey).decode());
    }

    @Override
    public Pkcs1String encode(RsaPrivateKey decoded) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
