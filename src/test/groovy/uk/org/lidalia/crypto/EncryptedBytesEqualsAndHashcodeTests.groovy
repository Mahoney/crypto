package uk.org.lidalia.crypto

import uk.org.lidalia.encoding.Bytes

class EncryptedBytesEqualsAndHashcodeTests extends EqualsAndHashcodeTests<Bytes> {

    EncryptedBytes instance1 = EncryptedBytes.of(randomBytes())
    Bytes equalToInstance1 = Bytes.of(instance1.array())
    EncryptedBytes instance2 = EncryptedBytes.of(randomBytes())
    Bytes equalToInstance2 = Bytes.of(instance2.array())

    byte[] randomBytes() {
        def bytes = new byte[256]
        new Random().nextBytes(bytes)
        bytes
    }
}
