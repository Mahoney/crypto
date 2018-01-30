package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class Pkcs8EncoderTests extends EncoderTests<RsaPrivateKey, String, Pkcs8String> {

    Pkcs8Encoder encoder = Pkcs8Encoder.pkcs8

    private static final RsaPrivateKey cached1 = RSA.generateKeyPair(1024)
    RsaPrivateKey instance1 = cached1

    private static final RsaPrivateKey cached2 = RSA.generateKeyPair(1024)
    RsaPrivateKey instance2 = cached2
}
