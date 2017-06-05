package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.DecryptKey;
import uk.org.lidalia.crypto.PrivateKey;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encodable;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;

import static java.nio.file.Files.newInputStream;
import static uk.org.lidalia.crypto.rsa.Pkcs1StringEncoder.pkcs1String;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public final class RsaPrivateKey
        extends RsaKey<RSAPrivateCrtKey>
        implements RSAPrivateCrtKey,
                   PrivateKey<RsaPublicKey, RsaPrivateKey, RsaPrivateKey>,
                   uk.org.lidalia.crypto.KeyPair<RsaPublicKey, RsaPrivateKey, RsaPrivateKey>,
                   DecryptKey<RsaPublicKey, RsaPrivateKey>,
                   Encodable<RsaPrivateKey> {

    public static RsaPrivateKey generate() throws IllegalStateException {
        return generate(4096);
    }

    public static RsaPrivateKey generate(int keySize) throws IllegalStateException {
        return RSA.generateKeyPair(keySize);
    }

    public static RsaPrivateKey of(KeyPair keyPair) {
        return of((RSAPrivateCrtKey) keyPair.getPrivate());
    }

    public static RsaPrivateKey loadFrom(Path path) throws IOException, InvalidEncoding {
        try (InputStream in = newInputStream(path)) {
            return of(Bytes.of(in).string());
        }
    }

    public static RsaPrivateKey loadDefault() throws IOException, InvalidEncoding {
        Path defaultRsaPrivateKey = Paths.get(System.getProperty("user.home"), ".ssh/id_rsa");
        return loadFrom(defaultRsaPrivateKey);
    }

    public static RsaPrivateKey of(String keyStr) throws InvalidEncoding {
        return of(pkcs1String.of(keyStr));
    }

    public static RsaPrivateKey of(final KeySpec privateKeySpec) throws InvalidKeySpecException {
        return RSA.privateKey(privateKeySpec);
    }

    public static RsaPrivateKey of(final RSAPrivateCrtKey decorated) {
        return new RsaPrivateKey(decorated);
    }

    public static RsaPrivateKey of(Encoded<RsaPrivateKey, ?> encoded) {
        return encoded.decode();
    }

    private final KeyPair keyPair;
    private final RsaPublicKey publicKey;

    private RsaPrivateKey(final RSAPrivateCrtKey decorated) {
        super(decorated);
        this.publicKey = buildPublicKey();
        this.keyPair = new KeyPair(publicKey, this);
    }

    private RsaPublicKey buildPublicKey() {
        try {
            final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                    getModulus(),
                    getPublicExponent()
            );
            return RsaPublicKey.of(publicKeySpec);
        } catch (final InvalidKeySpecException e) {
            throw new IllegalStateException(
                    "Creating an RSA public key from an RSA private key should always work. " +
                            "Using key="+ this, e);
        }
    }

    public KeyPair toKeyPair() {
        return keyPair;
    }

    @Override
    public RsaPublicKey publicKey() {
        return publicKey;
    }

    @Override
    public RsaPrivateKey privateKey() {
        return this;
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public BigInteger getPublicExponent() {
        return decorated.getPublicExponent();
    }

    @Override
    public BigInteger getPrimeP() {
        return decorated.getPrimeP();
    }

    @Override
    public BigInteger getPrimeQ() {
        return decorated.getPrimeQ();
    }

    @Override
    public BigInteger getPrimeExponentP() {
        return decorated.getPrimeExponentP();
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        return decorated.getPrimeExponentQ();
    }

    @Override
    public BigInteger getCrtCoefficient() {
        return decorated.getCrtCoefficient();
    }

    @Override
    public BigInteger getPrivateExponent() {
        return decorated.getPrivateExponent();
    }
}
