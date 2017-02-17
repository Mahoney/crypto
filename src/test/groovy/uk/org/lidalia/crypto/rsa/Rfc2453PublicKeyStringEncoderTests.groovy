package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class Rfc2453PublicKeyStringEncoderTests extends EncoderTests<RsaPublicKey, String, Rfc2453PublicKeyString> {

    Rfc2453PublicKeyStringEncoder encoder = Rfc2453PublicKeyStringEncoder.rfc2453PublicKeyString

    private static final RsaPrivateKey cached1 = RsaPrivateKey.generate()
    RsaPublicKey instance1 = cached1.publicKey()

    private static final RsaPrivateKey cached2 = RsaPrivateKey.generate()
    RsaPublicKey instance2 = cached2.publicKey()
}
