package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.HashAlgorithm;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static uk.org.lidalia.crypto.rsa.Algorithm.RSA;

public final class RsaPrivateCrtKey
        extends RsaKey<RSAPrivateCrtKey>
        implements RSAPrivateCrtKey {

    public static RsaPrivateCrtKey generate() throws IllegalStateException {
        try {
            final KeyPairGenerator keyPairGenerator
                    = KeyPairGenerator.getInstance(RSA.getName());
            keyPairGenerator.initialize(1024);
            return from(keyPairGenerator.generateKeyPair());
        } catch (final NoSuchAlgorithmException e) {
            throw new RequiredAlgorithmNotPresent(RSA.getName(), e);
        }
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
        final PrivateKey privateKey
                = RSA.getKeyFactory().generatePrivate(privateKeySpec);
        return from((RSAPrivateCrtKey) privateKey);
    }

    public static RsaPrivateCrtKey from(final RSAPrivateCrtKey decorated) {
        return new RsaPrivateCrtKey(decorated);
    }

    private final RsaPublicKey publicKey;

    private RsaPrivateCrtKey(final RSAPrivateCrtKey decorated) {
        super(decorated);
        this.publicKey = buildPublicKey();
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

    public byte[] signatureFor(
            final HashAlgorithm hashAlgorithm,
            final byte[]... contents) {
        final Signature signer = RSA.signatureFor(hashAlgorithm);
        try {
            signer.initSign(this);
            for (final byte[] content : contents) {
                signer.update(content);
            }
            return signer.sign();
        } catch (final Exception e) {
            throw new IllegalStateException(
                    "Signing a string with an RSA private key should always work. " +
                            "Using key="+ this, e);
        }
    }

    public KeyPair toKeyPair() {
        return new KeyPair(publicKey, this);
    }

    public RsaPublicKey getPublicKey() {
        return publicKey;
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
