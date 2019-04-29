package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.encoding.core.InvalidEncoding;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class Pkcs8Encoder implements Encoder<RsaPrivateKey, Bytes, Pkcs8> {

    public static final Pkcs8Encoder pkcs8 = new Pkcs8Encoder();

    private Pkcs8Encoder() {}

    @Override
    public Pkcs8 of(Bytes encodedKey) throws InvalidEncoding {
        return new Pkcs8(encodedKey, doDecode(encodedKey));
    }

    @Override
    public Pkcs8 encode(RsaPrivateKey decoded) {
        return new Pkcs8(doEncode(decoded), decoded);
    }


    private static Bytes doEncode(RsaPrivateKey decoded) {
        return Bytes.of(decoded.getEncoded());
    }

    private static RsaPrivateKey doDecode(Bytes raw) throws InvalidEncoding {
        try {
            final KeySpec privateKeySpec = new PKCS8EncodedKeySpec(raw.array());
            return RsaPrivateKey.of(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new InvalidEncoding(raw, "Unknown key format", e) {};
        }
    }

}
