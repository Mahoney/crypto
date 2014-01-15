package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.HashAlgorithm;

import java.math.BigInteger;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static uk.org.lidalia.crypto.rsa.RsaKeyUtils.rsaKeyFactory;

public class RsaPublicKey extends RsaKey<RSAPublicKey> implements RSAPublicKey {

    public static RsaPublicKey fromEncoded(byte[] publicKeyEncoded) throws InvalidKeySpecException {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyEncoded);
        return new RsaPublicKey((RSAPublicKey) rsaKeyFactory().generatePublic(publicKeySpec));
    }

    public RsaPublicKey(RSAPublicKey decorated) {
        super(decorated);
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
}
