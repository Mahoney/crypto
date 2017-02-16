package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class Pkcs8StringEncoderTests extends EncoderTests<RsaPrivateKey, String, Pkcs8String> {

    Pkcs8StringEncoder encoder = Pkcs8StringEncoder.pkcs8String
    RsaPrivateKey instance1 = RsaPrivateKey.generate()
    RsaPrivateKey instance2 = RsaPrivateKey.generate()
}
