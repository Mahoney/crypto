package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests
import uk.org.lidalia.lang.Bytes

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class Pkcs1EncoderTests extends EncoderTests<RsaPrivateKey, Bytes, Pkcs1> {

    Pkcs1Encoder encoder = Pkcs1Encoder.pkcs1

    private static final RsaPrivateKey cached1 = RSA.generateKeyPair(1024)
    RsaPrivateKey instance1 = cached1

    private static final RsaPrivateKey cached2 = RSA.generateKeyPair(1024)
    RsaPrivateKey instance2 = cached2
}
