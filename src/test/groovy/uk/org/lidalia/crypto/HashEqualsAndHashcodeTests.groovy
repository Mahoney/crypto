package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import uk.org.lidalia.EqualsAndHashcodeTests

import static uk.org.lidalia.crypto.HashAlgorithm.SHA256
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64

class HashEqualsAndHashcodeTests extends EqualsAndHashcodeTests<Hash> {

    String message1 = RandomStringUtils.random(100)
    String message2 = RandomStringUtils.random(100)

    Hash instance1A = SHA256.hash(message1)
    Hash instance1B = Hash.of(instance1A.bytes().array(), SHA256)
    Hash instance1C = Hash.of(base64.encode(instance1A.bytes()), SHA256)

    Hash instance2A = SHA256.hash(message2)
    Hash instance2B = Hash.of(instance2A.toString(), SHA256)
    Hash instance2C = Hash.of(instance2A.bytes(), SHA256)
}
