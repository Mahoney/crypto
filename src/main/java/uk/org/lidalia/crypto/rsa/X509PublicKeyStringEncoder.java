package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.core.ComposedEncoder;
import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.encoding.core.InvalidEncoding;

import static java.util.regex.Pattern.DOTALL;
import static java.util.regex.Pattern.compile;
import static uk.org.lidalia.crypto.rsa.X509PublicKeyEncoder.x509PublicKey;

public class X509PublicKeyStringEncoder implements Encoder<RsaPublicKey, String, X509PublicKeyString> {

    public static final X509PublicKeyStringEncoder x509PublicKeyString = new X509PublicKeyStringEncoder();

    private X509PublicKeyStringEncoder() {}

    @Override
    public X509PublicKeyString of(String encodedKey) throws InvalidEncoding {
        return new X509PublicKeyString(encodedKey, delegate.of(encodedKey).decode());
    }

    @Override
    public X509PublicKeyString encode(RsaPublicKey decoded) {
        return new X509PublicKeyString(delegate.encode(decoded).raw(), decoded);
    }

    private static final ComposedEncoder<RsaPublicKey, Bytes, String> delegate = new ComposedEncoder<>(
            x509PublicKey,
            new Base64StringFormatEncoder(
                    compile(
                            ".*-----BEGIN PUBLIC KEY-----(?<base64Block>.*)-----END PUBLIC KEY-----.*",
                            DOTALL
                    )
            )
    );
}
