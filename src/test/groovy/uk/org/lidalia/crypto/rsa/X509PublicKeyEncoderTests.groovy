package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.Bytes
import uk.org.lidalia.encoding.EncoderTests

class X509PublicKeyEncoderTests extends EncoderTests<RsaPublicKey, Bytes, X509PublicKey> {

    X509PublicKeyEncoder encoder = X509PublicKeyEncoder.x509PublicKey
    RsaPublicKey instance1 = RsaPrivateKey.generate().publicKey()
    RsaPublicKey instance2 = RsaPrivateKey.generate().publicKey()
}
