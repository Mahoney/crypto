package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static uk.org.lidalia.crypto.rsa.X509PublicKeyEncoder.x509PublicKey;

public class X509PublicKey extends CachedEncodedBase<RsaPublicKey, Bytes, X509PublicKey> implements Encoded<RsaPublicKey, Bytes, X509PublicKey> {

    X509PublicKey(Bytes raw) throws InvalidEncoding {
        super(raw, doDecode(raw));
    }

    X509PublicKey(RsaPublicKey key) {
        super(doEncode(key), key);
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

    @Override
    public X509PublicKeyEncoder encoder() {
        return x509PublicKey;
    }

}
