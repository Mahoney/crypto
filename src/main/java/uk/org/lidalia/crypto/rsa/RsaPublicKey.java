package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.HashAlgorithm;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import static uk.org.lidalia.crypto.Algorithm.RSA;

public final class RsaPublicKey
        extends RsaKey<RSAPublicKey>
        implements RSAPublicKey {

    public static RsaPublicKey fromEncoded(final byte[] publicKeyEncoded)
            throws InvalidKeySpecException {
        final X509EncodedKeySpec publicKeySpec
                = new X509EncodedKeySpec(publicKeyEncoded);
        return fromKeySpec(publicKeySpec);
    }

    public static RsaPublicKey fromKeySpec(final KeySpec publicKeySpec)
            throws InvalidKeySpecException {
        final PublicKey publicKey
                = RSA_KEY_FACTORY.generatePublic(publicKeySpec);
        return new RsaPublicKey((RSAPublicKey) publicKey);
    }

    public static RsaPublicKey from(final RSAPublicKey decorated) {
        return new RsaPublicKey(decorated);
    }

    private RsaPublicKey(final RSAPublicKey decorated) {
        super(decorated);
    }

    public boolean verifySignature(
            final byte[] signature,
            final HashAlgorithm hashAlgorithm,
            final byte[]... signedContents) {
        try {
            final Signature verifier = RSA.signatureFor(hashAlgorithm);
            verifier.initVerify(this);
            for (final byte[] content : signedContents) {
                verifier.update(content);
            }
            return verifier.verify(signature);
        } catch (final Exception e) {
            throw new IllegalStateException(
                    "Verifying a string with an RSA private key should always work. " +
                            "Using key="+ this, e);
        }
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public BigInteger getPublicExponent() {
        return decorated.getPublicExponent();
    }
}
