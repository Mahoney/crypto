package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.CipherAlgorithm;
import uk.org.lidalia.crypto.DecryptionFailedException;
import uk.org.lidalia.crypto.HashAlgorithm;
import uk.org.lidalia.encoding.Bytes;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public final class RsaPrivateCrtKey
        extends RsaKey<RSAPrivateCrtKey>
        implements RSAPrivateCrtKey,
                   uk.org.lidalia.crypto.PrivateKey<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey>,
                   uk.org.lidalia.crypto.KeyPair<RsaPublicKey, RsaPrivateCrtKey, RsaPrivateCrtKey> {

    public static RsaPrivateCrtKey generate() throws IllegalStateException {
        return generate(2048);
    }

    public static RsaPrivateCrtKey generate(int keysize) throws IllegalStateException {
        return RSA.generateKeyPair(keysize);
    }

    public static RsaPrivateCrtKey from(KeyPair keyPair) {
        return from((RSAPrivateCrtKey) keyPair.getPrivate());
    }

    public static RsaPrivateCrtKey fromEncoded(final byte[] privateKeyEncoded)
            throws InvalidKeySpecException {
        final KeySpec privateKeySpec
                = new PKCS8EncodedKeySpec(privateKeyEncoded);
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

    @Override
    public Bytes signatureFor(
            final HashAlgorithm hashAlgorithm,
            final Bytes contents) {
        final Signature signer = signatureFor(hashAlgorithm);
        try {
            signer.initSign(this);
            signer.update(contents.array());
            return Bytes.of(signer.sign());
        } catch (final Exception e) {
            throw new IllegalStateException(
                    "Signing a string with an RSA private key should always work. " +
                            "Using key="+ this, e);
        }
    }

    public Bytes decrypt(final Bytes encrypted, CipherAlgorithm cipherAlgorithm) throws DecryptionFailedException {
        try {
            return doCrypto(encrypted, cipherAlgorithm, Cipher.DECRYPT_MODE);
        } catch (final IllegalStateException e) {
            throw e;
        } catch (final Exception e) {
            throw new DecryptionFailedException(e);
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
