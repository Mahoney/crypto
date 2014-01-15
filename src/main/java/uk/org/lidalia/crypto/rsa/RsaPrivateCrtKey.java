package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.HashAlgorithm;

import java.math.BigInteger;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static uk.org.lidalia.crypto.rsa.RsaKeyUtils.rsaKeyFactory;

public class RsaPrivateCrtKey extends RsaKey<RSAPrivateCrtKey> implements RSAPrivateCrtKey {

    public static RsaPrivateCrtKey fromEncoded(byte[] privateKeyEncoded) throws InvalidKeySpecException {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
        return new RsaPrivateCrtKey((RSAPrivateCrtKey) rsaKeyFactory().generatePrivate(privateKeySpec));
    }

    public RsaPrivateCrtKey(RSAPrivateCrtKey decorated) {
        super(decorated);
    }

    public byte[] signatureFor(HashAlgorithm algorithm, final byte[]... contents) {
        final Signature signer = RsaKeyUtils.signatureFor(algorithm);
        try {
            signer.initSign(this);
            for (byte[] content : contents) {
                signer.update(content);
            }
            return signer.sign();
        } catch (Exception e) {
            throw new IllegalStateException("Signing a string with an RSA private key should always work. Using key="+ this, e);
        }
    }

    public RsaPublicKey getPublicKey() {
        try {
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                    getModulus(),
                    getPublicExponent()
            );
            return new RsaPublicKey((RSAPublicKey) rsaKeyFactory().generatePublic(publicKeySpec));
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Create an rsa public key from an rsa private key should always work. Using key="+ this, e);
        }
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
