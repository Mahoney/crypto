package uk.org.lidalia.encoding.base64

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Unroll
import uk.org.lidalia.lang.Bytes
import uk.org.lidalia.encoding.EncoderTests

import static uk.org.lidalia.encoding.base64.Base64Encoder.base64

class Base64EncoderTests extends EncoderTests<Bytes, String, Base64> {

    Base64Encoder encoder = base64

    Bytes instance1 = Bytes.of(randomBytes(500))
    Bytes instance2 = Bytes.of(randomBytes(500))

    def 'explicit test of raw encoded form'() {

        given:
            def base64 = encoder.of('AAF/gP8=')

        expect:
            base64.raw() == 'AAF/gP8='
            base64.toString() == 'AAF/gP8='
            base64.decode() == Bytes.of([0, 1, 127, -128, -1] as byte[])
    }

    def 'handles empty forms'() {

        expect:
            encoder.of('').decode() == Bytes.empty()
            encoder.encode(Bytes.empty()) == encoder.of('')
    }

    @Unroll
    def 'rejects invalid raw encoded form #invalidBase64'() {

        when:
            encoder.of(invalidBase64)

        then:
            def e = thrown(NotABase64EncodedString)
            e.message == "Not a base64 encoded string: [$invalidBase64]".toString()
            e.invalidEncoding == invalidBase64

        where:
            invalidBase64 << ['G', 'GG=', '-10', RandomStringUtils.random(16)]
    }

    private static def random = new Random()

    private static byte[] randomBytes(Integer upTo) {
        def bytes = new byte[random.nextInt(upTo)]
        random.nextBytes(bytes)
        bytes
    }

}
