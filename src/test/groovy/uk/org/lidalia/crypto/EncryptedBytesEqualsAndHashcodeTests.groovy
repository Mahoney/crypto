package uk.org.lidalia.crypto

import uk.org.lidalia.encoding.Bytes

class EncryptedBytesEqualsAndHashcodeTests extends EqualsAndHashcodeTests<Bytes> {

    EncryptedBytes instance1A = EncryptedBytes.of(randomBytes())
    Bytes instance1B = Bytes.of(instance1A.array())
    EncryptedBytes instance1C = Bytes.of(instance1A.array())

    EncryptedBytes instance2A = EncryptedBytes.of(randomBytes())
    Bytes instance2B = Bytes.of(instance2A.array())
    EncryptedBytes instance2C = Bytes.of(instance2A.array())

    byte[] randomBytes() {
        def bytes = new byte[256]
        new Random().nextBytes(bytes)
        bytes
    }
}
