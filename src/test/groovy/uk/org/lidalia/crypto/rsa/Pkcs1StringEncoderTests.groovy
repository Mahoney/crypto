package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class Pkcs1StringEncoderTests extends EncoderTests<RsaPrivateKey, String, Pkcs1String> {

    Pkcs1StringEncoder encoder = Pkcs1StringEncoder.pkcs1String

    private static final RsaPrivateKey cached1 = RsaPrivateKey.generate()
    RsaPrivateKey instance1 = cached1

    private static final RsaPrivateKey cached2 = RsaPrivateKey.generate()
    RsaPrivateKey instance2 = cached2
}
