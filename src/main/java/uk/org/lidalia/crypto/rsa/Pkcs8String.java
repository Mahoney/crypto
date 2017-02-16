package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.*;

import java.util.regex.Pattern;

import static uk.org.lidalia.crypto.rsa.Pkcs8Encoder.pkcs8;
import static uk.org.lidalia.crypto.rsa.Pkcs8StringEncoder.pkcs8String;

public class Pkcs8String extends CachedEncodedBase<RsaPrivateKey, String, Pkcs8String> implements Encoded<RsaPrivateKey, String, Pkcs8String> {

    Pkcs8String(String raw) throws InvalidEncoding {
        super(raw, doDecode(raw));
    }

    Pkcs8String(RsaPrivateKey key) {
        super(doEncode(key), key);
    }

    private static final Base64StringFormatEncoder<RsaPrivateKey> base64StringFormatEncoder = new Base64StringFormatEncoder<>(
            pkcs8,
            Pattern.compile(".*-----BEGIN PRIVATE KEY-----(?<base64Block>.*)-----END PRIVATE KEY-----.*", Pattern.DOTALL),
            true
    );

    private static String doEncode(RsaPrivateKey decoded) {
        return base64StringFormatEncoder.encode(decoded).raw();
    }

    private static RsaPrivateKey doDecode(String raw) throws InvalidEncoding {
        return base64StringFormatEncoder.of(raw).decode();
    }

    @Override
    public Pkcs8StringEncoder encoder() {
        return pkcs8String;
    }

}

