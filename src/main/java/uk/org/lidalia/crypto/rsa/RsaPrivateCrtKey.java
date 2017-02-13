package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.DecryptKey;
import uk.org.lidalia.crypto.PrivateKey;
import uk.org.lidalia.encoding.Bytes;
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
import static uk.org.lidalia.crypto.rsa.PrivateKeyReader.getRsaPrivateKeySpec;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public final class RsaPrivateCrtKey
        extends RsaKey<RSAPrivateCrtKey>
        implements RSAPrivateCrtKey,
                   PrivateKey<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey>,
                   uk.org.lidalia.crypto.KeyPair<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey>,
                   DecryptKey<RsaPublicKey, RsaPrivateCrtKey>{

    public static RsaPrivateCrtKey generate() throws IllegalStateException {
        return generate(2048);
    }

    public static RsaPrivateCrtKey generate(int keysize) throws IllegalStateException {
        return RSA.generateKeyPair(keysize);
    }

    public static RsaPrivateCrtKey from(KeyPair keyPair) {
        return from((RSAPrivateCrtKey) keyPair.getPrivate());
    }

    public static RsaPrivateCrtKey fromFile(Path path) throws IOException, InvalidKeySpecException, NotABase64EncodedString {
        try (InputStream in = newInputStream(path)) {
            return fromString(Bytes.of(in).string());
        }
    }

    private static Pattern keyRegex = Pattern.compile(".*-----BEGIN (?<pkcs1start>RSA )?PRIVATE KEY-----(?<base64Key>.*)-----END (?<pkcs1end>RSA )?PRIVATE KEY-----.*", Pattern.DOTALL);

    public static RsaPrivateCrtKey fromString(String keyStr) throws InvalidKeySpecException, NotABase64EncodedString, IOException {

        Matcher keyMatcher = keyRegex.matcher(keyStr);

        if (keyMatcher.matches()) {

            String base64KeyStr = keyMatcher.group("base64Key").replaceAll("\\s+", "");
            Bytes keyBytes = base64.of(base64KeyStr).decode();

            if (Objects.equals(keyMatcher.group("pkcs1start"), "RSA ")) {
                return fromKeySpec(getRsaPrivateKeySpec(keyBytes.array()));
            } else {
                return fromEncoded(keyBytes);
            }

        } else {
            throw new InvalidKeySpecException("Unknown key format");
        }
    }

    public static RsaPrivateCrtKey fromEncoded(final Bytes privateKeyEncoded)
            throws InvalidKeySpecException {
        final KeySpec privateKeySpec
                = new PKCS8EncodedKeySpec(privateKeyEncoded.array());
        return fromKeySpec(privateKeySpec);
    }

    public static RsaPrivateCrtKey fromKeySpec(final KeySpec privateKeySpec)
            throws InvalidKeySpecException {
        return RSA.privateKey(privateKeySpec);
    }

    public static RsaPrivateCrtKey from(final RSAPrivateCrtKey decorated) {
        return new RsaPrivateCrtKey(decorated);
    }

    private final KeyPair keyPair;
    private final RsaPublicKey publicKey;

    private RsaPrivateCrtKey(final RSAPrivateCrtKey decorated) {
        super(decorated);
        this.publicKey = buildPublicKey();
        this.keyPair = new KeyPair(publicKey, this);
    }

    @Override
    public String export() {
        return exportPkcs8();
    }

    public String exportPkcs1() {
        return "-----BEGIN RSA PRIVATE KEY-----\n"+
                Bytes.of(getEncoded()).encode().toString().replaceAll("(.{64})", "$1\n")+
                "\n-----END RSA PRIVATE KEY-----\n";
    }

    public String exportPkcs8() {
        return "-----BEGIN PRIVATE KEY-----\n"+
                Bytes.of(getEncoded()).encode().toString().replaceAll("(.{64})", "$1\n")+
                "\n-----END PRIVATE KEY-----\n";
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
    public RsaPrivateCrtKey privateKey() {
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
