package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class X509PublicKeyStringEncoderTests extends EncoderTests<RsaPublicKey, String, X509PublicKeyString> {

    X509PublicKeyStringEncoder encoder = X509PublicKeyStringEncoder.x509PublicKeyString

    private static final RsaPrivateKey cached1 = RsaPrivateKey.generate()
    RsaPublicKey instance1 = cached1.publicKey()

    private static final RsaPrivateKey cached2 = RsaPrivateKey.generate()
    RsaPublicKey instance2 = cached2.publicKey()
}
