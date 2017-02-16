package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class X509PublicKeyStringEncoderTests extends EncoderTests<RsaPublicKey, String, X509PublicKeyString> {

    X509PublicKeyStringEncoder encoder = X509PublicKeyStringEncoder.x509PublicKeyString
    RsaPublicKey instance1 = RsaPrivateKey.generate().publicKey()
    RsaPublicKey instance2 = RsaPrivateKey.generate().publicKey()
}
