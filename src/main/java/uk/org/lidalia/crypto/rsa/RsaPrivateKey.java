package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.DecryptKey;
import uk.org.lidalia.crypto.PrivateKey;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encodable;
import uk.org.lidalia.encoding.InvalidEncoding;
import uk.org.lidalia.encoding.base64.NotABase64EncodedString;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.file.Files.newInputStream;
import static uk.org.lidalia.crypto.rsa.Pkcs1Encoder.pkcs1;
import static uk.org.lidalia.crypto.rsa.Pkcs8Encoder.pkcs8;
import static uk.org.lidalia.crypto.rsa.PrivateKeyReader.getRsaPrivateKeySpec;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public final class RsaPrivateKey
        extends RsaKey<RSAPrivateCrtKey>
        implements RSAPrivateCrtKey,
                   PrivateKey<RsaPublicKey, RsaPrivateKey, RsaPrivateKey>,
                   uk.org.lidalia.crypto.KeyPair<RsaPublicKey, RsaPrivateKey, RsaPrivateKey>,
                   DecryptKey<RsaPublicKey, RsaPrivateKey>,
                   Encodable<RsaPrivateKey> {

    public static RsaPrivateKey generate() throws IllegalStateException {
        return generate(2048);
    }

    public static RsaPrivateKey generate(int keysize) throws IllegalStateException {
        return RSA.generateKeyPair(keysize);
    }

    public static RsaPrivateKey from(KeyPair keyPair) {
        return from((RSAPrivateCrtKey) keyPair.getPrivate());
    }

    public static RsaPrivateKey fromFile(Path path) throws IOException, InvalidEncoding {
        try (InputStream in = newInputStream(path)) {
            return fromString(Bytes.of(in).string());
        }
    }

    public static RsaPrivateKey fromString(String keyStr) throws InvalidEncoding {
        return pkcs1.of(keyStr).decode();
    }

    public static RsaPrivateKey fromEncoded(final Bytes privateKeyEncoded)
            throws InvalidKeySpecException {
        final KeySpec privateKeySpec
                = new PKCS8EncodedKeySpec(privateKeyEncoded.array());
        return fromKeySpec(privateKeySpec);
    }

    public static RsaPrivateKey fromKeySpec(final KeySpec privateKeySpec)
            throws InvalidKeySpecException {
        return RSA.privateKey(privateKeySpec);
    }

    public static RsaPrivateKey from(final RSAPrivateCrtKey decorated) {
        return new RsaPrivateKey(decorated);
    }

    private final KeyPair keyPair;
    private final RsaPublicKey publicKey;

    private RsaPrivateKey(final RSAPrivateCrtKey decorated) {
        super(decorated);
        this.publicKey = buildPublicKey();
        this.keyPair = new KeyPair(publicKey, this);
    }

    @Override
    public String export() {
        return encode(pkcs8).toString();
    }

    private RsaPublicKey buildPublicKey() {
        try {
            final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                    getModulus(),
                    getPublicExponent()
            );
            return RsaPublicKey.fromKeySpec(publicKeySpec);
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
