package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.PublicEncryptKey;
import uk.org.lidalia.encoding.core.Encodable;
import uk.org.lidalia.encoding.core.Encoded;
import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.encoding.core.InvalidEncoding;
import uk.org.lidalia.lang.Bytes;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import static java.nio.file.Files.newInputStream;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;
import static uk.org.lidalia.crypto.rsa.SshPublicKeyStringEncoder.sshPublicKeyString;
import static uk.org.lidalia.crypto.rsa.X509PublicKeyStringEncoder.x509PublicKeyString;

public final class RsaPublicKey
        extends RsaKey<RSAPublicKey>
        implements RSAPublicKey, PublicEncryptKey<Rsa>,
        Encodable<RsaPublicKey> {

    public static RsaPublicKey of(final KeySpec publicKeySpec) throws InvalidKeySpecException {
        return RSA.publicKey(publicKeySpec);
    }

    public static RsaPublicKey of(final RSAPublicKey decorated) {
        return new RsaPublicKey(decorated);
    }

    public static RsaPublicKey loadFrom(Path path) throws IOException, InvalidEncoding {
        try (InputStream in = newInputStream(path)) {
            return of(Bytes.of(in).string());
        }
    }

    @SuppressWarnings("unused")
    public static RsaPublicKey loadDefault() throws IOException, InvalidEncoding {
        Path defaultRsaPrivateKey = Paths.get(System.getProperty("user.home"), ".ssh/id_rsa.pub");
        return loadFrom(defaultRsaPrivateKey);
    }

    public static RsaPublicKey of(String keyStr) throws InvalidEncoding {
        return of(encoderFor(keyStr).of(keyStr));
    }

    private static Encoder<RsaPublicKey, String, ?> encoderFor(String keyStr) {
        if (keyStr.startsWith("ssh-rsa ")) {
            return sshPublicKeyString;
        } else {
            return x509PublicKeyString;
        }
    }

    public static RsaPublicKey of(Encoded<RsaPublicKey, ?> encoded) {
        return encoded.decode();
    }

    private RsaPublicKey(final RSAPublicKey decorated) {
        super(decorated);
    }

    public SshPublicKeyString encode() {
        return encode(sshPublicKeyString);
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
