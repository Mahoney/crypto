package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.core.ComposedEncoder;
import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.encoding.core.InvalidEncoding;

import java.util.regex.Pattern;

import static java.util.regex.Pattern.compile;
import static uk.org.lidalia.crypto.rsa.Pkcs8Encoder.pkcs8;

public class Pkcs8StringEncoder implements Encoder<RsaPrivateKey, String, Pkcs8String> {

    public static final Pkcs8StringEncoder pkcs8String = new Pkcs8StringEncoder();

    private Pkcs8StringEncoder() {}

    @Override
    public Pkcs8String of(String encodedKey) throws InvalidEncoding {
        return new Pkcs8String(encodedKey, delegate.of(encodedKey).decode());
    }

    @Override
    public Pkcs8String encode(RsaPrivateKey decoded) {
        return new Pkcs8String(delegate.encode(decoded).raw(), decoded);
    }

    private static final ComposedEncoder<RsaPrivateKey, Bytes, String> delegate = new ComposedEncoder<>(
            pkcs8,
            new Base64StringFormatEncoder(
                    compile(
                            ".*-----BEGIN PRIVATE KEY-----(?<base64Block>.*)-----END PRIVATE KEY-----.*",
                            Pattern.DOTALL
                    )
            )
    );
}
