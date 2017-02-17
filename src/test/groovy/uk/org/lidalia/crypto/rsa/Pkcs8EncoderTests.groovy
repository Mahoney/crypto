package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class Pkcs8EncoderTests extends EncoderTests<RsaPrivateKey, String, Pkcs8String> {

    Pkcs8Encoder encoder = Pkcs8Encoder.pkcs8

    private static final RsaPrivateKey cached1 = RsaPrivateKey.generate()
    RsaPrivateKey instance1 = cached1

    private static final RsaPrivateKey cached2 = RsaPrivateKey.generate()
    RsaPrivateKey instance2 = cached2
}
