package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.encoding.core.InvalidEncoding;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class X509PublicKeyEncoder implements Encoder<RsaPublicKey, Bytes, X509PublicKey> {

    public static final X509PublicKeyEncoder x509PublicKey = new X509PublicKeyEncoder();

    private X509PublicKeyEncoder() {}

    @Override
    public X509PublicKey of(Bytes encodedKey) throws InvalidEncoding {
        return new X509PublicKey(encodedKey, doDecode(encodedKey));
    }

    @Override
    public X509PublicKey encode(RsaPublicKey decoded) {
        return new X509PublicKey(doEncode(decoded), decoded);
    }


    private static Bytes doEncode(RsaPublicKey decoded) {
        return Bytes.of(decoded.getEncoded());
    }

    private static RsaPublicKey doDecode(Bytes raw) throws InvalidEncoding {
        try {
            return RsaPublicKey.of(new X509EncodedKeySpec(raw.array()));
        } catch (InvalidKeySpecException e) {
            throw new InvalidEncoding(raw, "Unknown key format", e) {};
        }
    }
}
