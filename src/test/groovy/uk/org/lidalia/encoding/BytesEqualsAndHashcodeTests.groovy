package uk.org.lidalia.encoding

import uk.org.lidalia.EqualsAndHashcodeTests

class BytesEqualsAndHashcodeTests extends EqualsAndHashcodeTests<Bytes> {

    byte[] raw1 = randomBytes(500)
    Bytes instance1A = Bytes.of(raw1)
    Bytes instance1B = Bytes.of(raw1)
    Bytes instance1C = Bytes.of(instance1A.inputStream())

    byte[] raw2 = randomBytes(10)
    Bytes instance2A = Bytes.of(Arrays.copyOfRange(raw2, 5, 9))
    Bytes instance2B = Bytes.of(raw2).drop(4).subList(1, 5)
    Bytes instance2C = Bytes.of(instance2B.array())

    private static def random = new Random()

    private static byte[] randomBytes(Integer number) {
        def bytes = new byte[number]
        random.nextBytes(bytes)
        bytes
    }
}
