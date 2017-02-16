package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.util.regex.Pattern;

import static uk.org.lidalia.crypto.rsa.Pkcs1Encoder.pkcs1;
import static uk.org.lidalia.crypto.rsa.Pkcs1StringEncoder.pkcs1String;

public class Pkcs1String extends CachedEncodedBase<RsaPrivateKey, String, Pkcs1String> implements Encoded<RsaPrivateKey, String, Pkcs1String> {

    private static final Base64StringFormatEncoder<RsaPrivateKey> base64StringFormatEncoder = new Base64StringFormatEncoder<>(
            pkcs1,
            Pattern.compile(".*-----BEGIN RSA PRIVATE KEY-----(?<base64Block>.*)-----END RSA PRIVATE KEY-----.*", Pattern.DOTALL)
    );

    Pkcs1String(String raw) throws InvalidEncoding {
        super(raw, base64StringFormatEncoder.of(raw).decode());
    }

    @Override
    public Pkcs1StringEncoder encoder() {
        return pkcs1String;
    }

}
