package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.asn1.Asn1Sequence
import uk.org.lidalia.encoding.EncoderTests

class Pkcs1Asn1EncoderTests extends EncoderTests<RsaPrivateKey, Asn1Sequence, Pkcs1Asn1> {

    Pkcs1Asn1Encoder encoder = Pkcs1Asn1Encoder.pkcs1Asn1

    private static final RsaPrivateKey cached1 = RsaPrivateKey.generate()
    RsaPrivateKey instance1 = cached1

    private static final RsaPrivateKey cached2 = RsaPrivateKey.generate()
    RsaPrivateKey instance2 = cached2
}
