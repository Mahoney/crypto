package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.HashAlgorithm;
import uk.org.lidalia.encoding.Bytes;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import static uk.org.lidalia.crypto.rsa.Rsa.RSA;

public final class RsaPublicKey
        extends RsaKey<RSAPublicKey>
        implements RSAPublicKey, uk.org.lidalia.crypto.PublicKey<RsaPublicKey, RsaPrivateCrtKey> {

    public static RsaPublicKey fromEncoded(final byte[] publicKeyEncoded)
            throws InvalidKeySpecException {
        final X509EncodedKeySpec publicKeySpec
                = new X509EncodedKeySpec(publicKeyEncoded);
        return fromKeySpec(publicKeySpec);
    }

    public static RsaPublicKey fromKeySpec(final KeySpec publicKeySpec)
            throws InvalidKeySpecException {
        final PublicKey publicKey
                = RSA.keyFactory().generatePublic(publicKeySpec);
        return from((RSAPublicKey) publicKey);
    }

    public static RsaPublicKey from(final RSAPublicKey decorated) {
        return new RsaPublicKey(decorated);
    }

    private RsaPublicKey(final RSAPublicKey decorated) {
        super(decorated);
    }

    public boolean verifySignature(
        final Bytes signature,
        final HashAlgorithm hashAlgorithm,
        final Bytes signedContents
    ) {
        try {
            final Signature verifier = RSA.signatureFor(hashAlgorithm);
            verifier.initVerify(this);
            verifier.update(signedContents.array());
            return verifier.verify(signature.array());
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
