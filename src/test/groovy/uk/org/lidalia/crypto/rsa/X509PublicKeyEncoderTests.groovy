package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.Bytes
import uk.org.lidalia.encoding.EncoderTests

class X509PublicKeyEncoderTests extends EncoderTests<RsaPublicKey, Bytes, X509PublicKey> {

    X509PublicKeyEncoder encoder = X509PublicKeyEncoder.x509PublicKey

    private static final RsaPrivateKey cached1 = RsaPrivateKey.generate()
    RsaPublicKey instance1 = cached1.publicKey()

    private static final RsaPrivateKey cached2 = RsaPrivateKey.generate()
    RsaPublicKey instance2 = cached2.publicKey()
}
