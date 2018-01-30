package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class X509PublicKeyStringEncoderTests extends EncoderTests<RsaPublicKey, String, X509PublicKeyString> {

    X509PublicKeyStringEncoder encoder = X509PublicKeyStringEncoder.x509PublicKeyString

    private static final RsaPrivateKey cached1 = RSA.generateKeyPair(1024)
    RsaPublicKey instance1 = cached1.publicKey()

    private static final RsaPrivateKey cached2 = RSA.generateKeyPair(1024)
    RsaPublicKey instance2 = cached2.publicKey()
}
