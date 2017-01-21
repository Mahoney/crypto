package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils

import static uk.org.lidalia.crypto.HashAlgorithm.SHA256

class HashEqualsAndHashcodeTests extends EqualsAndHashcodeTests<Hash> {

    String message1 = RandomStringUtils.random(100)
    String message2 = RandomStringUtils.random(100)

    Hash instance1A = SHA256.hash(message1)
    Hash instance1B = SHA256.hash(message1)
    Hash instance1C = SHA256.hash(message1)

    Hash instance2A = SHA256.hash(message2)
    Hash instance2B = SHA256.hash(message2)
    Hash instance2C = SHA256.hash(message2)
}
