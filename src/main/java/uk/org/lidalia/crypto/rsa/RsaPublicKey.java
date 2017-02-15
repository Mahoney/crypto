package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.EncryptKey;
import uk.org.lidalia.crypto.PublicKey;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import static java.nio.file.Files.newInputStream;
import static uk.org.lidalia.crypto.rsa.Rfc2453PublicKeyEncoder.rfc2453PublicKey;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public final class RsaPublicKey
        extends RsaKey<RSAPublicKey>
        implements RSAPublicKey, PublicKey<RsaPublicKey, RsaPrivateKey, RsaPrivateKey>,
        EncryptKey<RsaPublicKey, RsaPrivateKey> {

    public static RsaPublicKey fromEncoded(final Bytes publicKeyEncoded)
            throws InvalidKeySpecException {
        final X509EncodedKeySpec publicKeySpec
                = new X509EncodedKeySpec(publicKeyEncoded.array());
        return fromKeySpec(publicKeySpec);
    }

    public static RsaPublicKey fromKeySpec(final KeySpec publicKeySpec)
            throws InvalidKeySpecException {
        return RSA.publicKey(publicKeySpec);
    }

    public static RsaPublicKey from(final RSAPublicKey decorated) {
        return new RsaPublicKey(decorated);
    }

    private RsaPublicKey(final RSAPublicKey decorated) {
        super(decorated);
    }

    @Override
    public String export() {
        return exportX509();
    }

    public String exportX509() {
        return "-----BEGIN PUBLIC KEY-----\n"+
                Bytes.of(getEncoded()).encode().toString().replaceAll("(.{64})", "$1\n")+
                "\n-----END PUBLIC KEY-----\n";
    }

    public static RsaPublicKey fromFile(Path path) throws IOException, InvalidEncoding {
        try (InputStream in = newInputStream(path)) {
            return fromString(Bytes.of(in).string());
        }
    }

    public static RsaPublicKey fromString(String keyStr) throws InvalidEncoding {
        return rfc2453PublicKey.of(keyStr).decode();
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public BigInteger getPublicExponent() {
        return decorated.getPublicExponent();
    }
}
