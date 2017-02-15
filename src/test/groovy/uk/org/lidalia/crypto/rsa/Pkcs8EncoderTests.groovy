package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class Pkcs8EncoderTests extends EncoderTests<RsaPrivateKey, String, Pkcs8> {

    Pkcs8Encoder encoder = Pkcs8Encoder.pkcs8
    RsaPrivateKey instance1 = RsaPrivateKey.generate()
    RsaPrivateKey instance2 = RsaPrivateKey.generate()
}
