package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.ComposedEncoder;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import static java.util.regex.Pattern.DOTALL;
import static java.util.regex.Pattern.compile;
import static uk.org.lidalia.crypto.rsa.Rfc2453PublicKeyEncoder.rfc2453PublicKey;

public class Rfc2453PublicKeyStringEncoder implements Encoder<RsaPublicKey, String, Rfc2453PublicKeyString> {

    public static final Rfc2453PublicKeyStringEncoder rfc2453PublicKeyString = new Rfc2453PublicKeyStringEncoder();

    @Override
    public Rfc2453PublicKeyString of(String encoded) throws InvalidEncoding {
        return new Rfc2453PublicKeyString(encoded, delegate.of(encoded).decode());
    }

    @Override
    public Rfc2453PublicKeyString encode(RsaPublicKey rsaPublicKey) {
        return new Rfc2453PublicKeyString(doEncode(rsaPublicKey), rsaPublicKey);
    }

    private static final ComposedEncoder<RsaPublicKey, Bytes, String> delegate = new ComposedEncoder<>(
            rfc2453PublicKey,
            new Base64StringFormatEncoder(compile("^ssh-rsa (?<base64Block>[^ ]*)( .*)?\\n?$", DOTALL))
    );

    private static String doEncode(RsaPublicKey rsaPublicKey) {
        return "ssh-rsa " + rfc2453PublicKey.encode(rsaPublicKey).raw().encode();
    }
}
