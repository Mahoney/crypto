package uk.org.lidalia.crypto;

import java.math.BigInteger;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class RsaPublicKey implements RSAPublicKey {

    public static RsaPublicKey fromEncoded(byte[] publicKeyEncoded) throws InvalidKeySpecException {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyEncoded);
        return new RsaPublicKey((RSAPublicKey) RsaKeyUtils.rsaKeyFactory().generatePublic(publicKeySpec));
    }

    private final RSAPublicKey decorated;

    public RsaPublicKey(RSAPublicKey decorated) {
        this.decorated = decorated;
    }

    public boolean verifySignature(final byte[] signature, final HashAlgorithm hashAlgorithm, final byte[]... signedContents) {
        try {
            final Signature verifier = RsaKeyUtils.signatureFor(hashAlgorithm);
            verifier.initVerify(this);
            for (byte[] content : signedContents) {
                verifier.update(content);
            }
            return verifier.verify(signature);
        } catch (Exception e) {
            throw new IllegalStateException("Verifying a string with an RSA private key should always work. Using key="+ this, e);
        }
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public BigInteger getPublicExponent() {
        return decorated.getPublicExponent();
    }

    @Override
    public String getAlgorithm() {
        return decorated.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return decorated.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return decorated.getEncoded();
    }

    @Override
    public BigInteger getModulus() {
        return decorated.getModulus();
    }

    @Override
    public String toString() {
        return decorated.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RSAPublicKey)) return false;

        RSAPublicKey publicKey = (RSAPublicKey) o;

        return decorated.equals(publicKey);
    }

    @Override
    public int hashCode() {
        return decorated.hashCode();
    }
}
