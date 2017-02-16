package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import static uk.org.lidalia.crypto.rsa.Pkcs8Encoder.pkcs8;

public class Pkcs8 extends CachedEncodedBase<RsaPrivateKey, Bytes, Pkcs8> implements Encoded<RsaPrivateKey, Bytes, Pkcs8> {

    Pkcs8(Bytes raw) throws InvalidEncoding {
        super(raw, doDecode(raw));
    }

    Pkcs8(RsaPrivateKey key) {
        super(doEncode(key), key);
    }

    private static Bytes doEncode(RsaPrivateKey decoded) {
        return Bytes.of(decoded.getEncoded());
    }

    private static RsaPrivateKey doDecode(Bytes raw) throws InvalidEncoding {
        try {
            final KeySpec privateKeySpec
                    = new PKCS8EncodedKeySpec(raw.array());
            return RsaPrivateKey.of(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new InvalidEncoding(raw, "Unknown key format", e) {};
        }
    }

    @Override
    public Pkcs8Encoder encoder() {
        return pkcs8;
    }

}
