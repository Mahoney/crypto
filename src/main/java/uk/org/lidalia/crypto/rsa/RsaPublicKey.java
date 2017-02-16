package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.EncryptKey;
import uk.org.lidalia.crypto.PublicKey;
import uk.org.lidalia.encoding.*;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import static java.nio.file.Files.newInputStream;
import static uk.org.lidalia.crypto.rsa.Rfc2453PublicKeyStringEncoder.rfc2453PublicKeyString;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;
import static uk.org.lidalia.crypto.rsa.X509PublicKeyStringEncoder.x509PublicKeyString;

public final class RsaPublicKey
        extends RsaKey<RSAPublicKey>
        implements RSAPublicKey, PublicKey<RsaPublicKey, RsaPrivateKey, RsaPrivateKey>,
        EncryptKey<RsaPublicKey, RsaPrivateKey>,
        Encodable<RsaPublicKey> {

    public static RsaPublicKey of(final KeySpec publicKeySpec) throws InvalidKeySpecException {
        return RSA.publicKey(publicKeySpec);
    }

    public static RsaPublicKey of(final RSAPublicKey decorated) {
        return new RsaPublicKey(decorated);
    }

    public static RsaPublicKey of(Path path) throws IOException, InvalidEncoding {
        try (InputStream in = newInputStream(path)) {
            return of(Bytes.of(in).string());
        }
    }

    public static RsaPublicKey of(String keyStr) throws InvalidEncoding {
        return of(encoderFor(keyStr).of(keyStr));
    }

    private static Encoder<RsaPublicKey, String, ?> encoderFor(String keyStr) {
        if (keyStr.startsWith("ssh-rsa ")) {
            return rfc2453PublicKeyString;
        } else {
            return x509PublicKeyString;
        }
    }

    public static RsaPublicKey of(Encoded<RsaPublicKey, ?, ?> encoded) throws InvalidEncoding {
        return encoded.decode();
    }

    private RsaPublicKey(final RSAPublicKey decorated) {
        super(decorated);
    }

    public Rfc2453PublicKeyString encode() {
        return encode(rfc2453PublicKeyString);
    }

    @Override
    public String toString() {
        return encode().raw();
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public BigInteger getPublicExponent() {
        return decorated.getPublicExponent();
    }
}
