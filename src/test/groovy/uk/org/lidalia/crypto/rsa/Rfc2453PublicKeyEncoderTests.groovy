package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class Rfc2453PublicKeyEncoderTests extends EncoderTests<RsaPublicKey, String, Rfc2453PublicKeyString> {

    Rfc2453PublicKeyStringEncoder encoder = Rfc2453PublicKeyStringEncoder.rfc2453PublicKeyString
    RsaPublicKey instance1 = RsaPrivateKey.generate().publicKey()
    RsaPublicKey instance2 = RsaPrivateKey.generate().publicKey()
}
