package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Shared
import uk.org.lidalia.crypto.rsa.RsaPrivateKey

import static uk.org.lidalia.crypto.HashAlgorithm.SHA256

class SignatureEqualsAndHashcodeTests extends EqualsAndHashcodeTests<Signature> {

    String message1 = RandomStringUtils.random(100)
    String message2 = RandomStringUtils.random(100)

    @Shared privateKey = RsaPrivateKey.generate()

    Signature instance1A = privateKey.sign(message1)
    Signature instance1B = Signature.of(instance1A.bytes().array(), SHA256)
    Signature instance1C = Signature.of(instance1A.bytes().encode(), SHA256)

    Signature instance2A = privateKey.sign(message2)
    Signature instance2B = Signature.of(instance2A.bytes().encode(), SHA256)
    Signature instance2C = Signature.of(instance2A.bytes(), SHA256)
}
