package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Shared
import uk.org.lidalia.EqualsAndHashcodeTests

import static uk.org.lidalia.crypto.HashAlgorithm.SHA256
import static uk.org.lidalia.crypto.rsa.Rsa.RSA
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64

class SignatureEqualsAndHashcodeTests extends EqualsAndHashcodeTests<Signature> {

    String message1 = RandomStringUtils.random(100)
    String message2 = RandomStringUtils.random(100)

    @Shared privateKey = RSA.generateKeyPair(1024)

    Signature instance1A = privateKey.sign(message1)
    Signature instance1B = Signature.of(instance1A.bytes().array(), SHA256)
    Signature instance1C = Signature.of(base64.encode(instance1A.bytes()), SHA256)

    Signature instance2A = privateKey.sign(message2)
    Signature instance2B = Signature.of(base64.encode(instance2A.bytes()), SHA256)
    Signature instance2C = Signature.of(instance2A.bytes(), SHA256)
}
