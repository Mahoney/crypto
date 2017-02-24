package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.Bytes
import uk.org.lidalia.encoding.EncoderTests

class Pkcs1EncoderTests extends EncoderTests<RsaPrivateKey, Bytes, Pkcs1> {

    Pkcs1Encoder encoder = Pkcs1Encoder.pkcs1

    private static final RsaPrivateKey cached1 = RsaPrivateKey.generate()
    RsaPrivateKey instance1 = cached1

    private static final RsaPrivateKey cached2 = RsaPrivateKey.generate()
    RsaPrivateKey instance2 = cached2
}
