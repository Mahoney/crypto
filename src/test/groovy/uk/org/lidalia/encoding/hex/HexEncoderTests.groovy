package uk.org.lidalia.encoding.hex

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Unroll
import uk.org.lidalia.lang.Bytes
import uk.org.lidalia.encoding.EncoderTests

import static uk.org.lidalia.encoding.hex.HexEncoder.hex

class HexEncoderTests extends EncoderTests<Bytes, String, Hex> {

    HexEncoder encoder = hex

    Bytes instance1 = Bytes.of(randomBytes(500))
    Bytes instance2 = Bytes.of(randomBytes(500))

    @Unroll
    def 'raw encoded form #hexString is case insensitive'() {

        given:
            def hex = encoder.of(hexString)

        expect:
            hex.raw() == hexString
            hex.toString() == hexString
            hex.decode() == Bytes.of([0, 1, 127, -128, -1] as byte[])

        where:
            hexString << [
                    '00017F80FF',
                    '00017f80ff'
            ]
    }

    def 'handles empty forms'() {

        expect:
            encoder.of('').decode() == Bytes.empty()
            encoder.encode(Bytes.empty()) == encoder.of('')
    }

    @Unroll
    def 'rejects invalid raw encoded form #invalidHex'() {

        when:
            encoder.of(invalidHex)

        then:
            def e = thrown(NotAHexEncodedString)
            e.message == "Not a hex encoded string: [$invalidHex]".toString()
            e.invalidEncoding == invalidHex

        where:
            invalidHex << ['G', 'GG', '-10', RandomStringUtils.random(16)]
    }

    private static def random = new Random()

    private static byte[] randomBytes(Integer upTo) {
        def bytes = new byte[random.nextInt(upTo)]
        random.nextBytes(bytes)
        bytes
    }

}
