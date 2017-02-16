package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.ComposedEncoder;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.util.regex.Pattern;

import static java.util.regex.Pattern.compile;
import static uk.org.lidalia.crypto.rsa.Pkcs8Encoder.pkcs8;
import static uk.org.lidalia.crypto.rsa.Pkcs8StringEncoder.pkcs8String;

public class Pkcs8String extends CachedEncodedBase<RsaPrivateKey, String, Pkcs8String> implements Encoded<RsaPrivateKey, String, Pkcs8String> {

    private static final ComposedEncoder<RsaPrivateKey, Bytes, String> base64StringFormatEncoder = new ComposedEncoder<>(
            pkcs8,
            new Base64StringFormatEncoder(
                    compile(
                            ".*-----BEGIN PRIVATE KEY-----(?<base64Block>.*)-----END PRIVATE KEY-----.*",
                            Pattern.DOTALL
                    )
            )
    );

    Pkcs8String(String raw) throws InvalidEncoding {
        super(raw, base64StringFormatEncoder.of(raw).decode());
    }

    Pkcs8String(RsaPrivateKey key) {
        super(base64StringFormatEncoder.encode(key).raw(), key);
    }

    @Override
    public Pkcs8StringEncoder encoder() {
        return pkcs8String;
    }

}

