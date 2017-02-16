package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.ComposedEncoder;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import static java.util.regex.Pattern.DOTALL;
import static java.util.regex.Pattern.compile;
import static uk.org.lidalia.crypto.rsa.Rfc2453PublicKeyEncoder.rfc2453PublicKey;

public class Rfc2453PublicKeyString extends CachedEncodedBase<RsaPublicKey, String, Rfc2453PublicKeyString> implements Encoded<RsaPublicKey, String, Rfc2453PublicKeyString> {

    private static final ComposedEncoder<RsaPublicKey, Bytes, String> base64StringFormatEncoder = new ComposedEncoder<>(
        rfc2453PublicKey,
        new Base64StringFormatEncoder(
            compile("^ssh-rsa (?<base64Block>[^ ]*)( .*)?\\n?$", DOTALL)
        )
    );

    Rfc2453PublicKeyString(String raw) throws InvalidEncoding {
        super(raw, base64StringFormatEncoder.of(raw).decode());
    }

    Rfc2453PublicKeyString(RsaPublicKey rsaPublicKey) {
        super(doEncode(rsaPublicKey), rsaPublicKey);
    }

    private static String doEncode(RsaPublicKey rsaPublicKey) {
        return "ssh-rsa " + rfc2453PublicKey.encode(rsaPublicKey).raw().encode();
    }

    @Override
    public Rfc2453PublicKeyStringEncoder encoder() {
        return Rfc2453PublicKeyStringEncoder.rfc2453PublicKeyString;
    }
}
