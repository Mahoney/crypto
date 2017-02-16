package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class Rfc2453PublicKeyEncoderTests extends EncoderTests<RsaPublicKey, String, Rfc2453PublicKey> {

    Rfc2453PublicKeyEncoder encoder = Rfc2453PublicKeyEncoder.rfc2453PublicKey
    RsaPublicKey instance1 = RsaPrivateKey.generate().publicKey()
    RsaPublicKey instance2 = RsaPrivateKey.generate().publicKey()
}