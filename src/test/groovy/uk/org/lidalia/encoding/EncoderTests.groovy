package uk.org.lidalia.encoding

import uk.org.lidalia.EqualsAndHashcodeTests
import uk.org.lidalia.encoding.core.Encoded
import uk.org.lidalia.encoding.core.Encoder

abstract class EncoderTests<Decoded, RawEncoded, E extends Encoded<Decoded, RawEncoded>> extends EqualsAndHashcodeTests<E> {

    abstract Encoder<Decoded, RawEncoded, E> getEncoder()

    abstract Decoded getInstance1()
    abstract Decoded getInstance2()

    E getInstance1A() { encoder.encode(instance1) }
    E getInstance1B() { encoder.encode(instance1) }
    E getInstance1C() { encoder.encode(instance1) }
    
    E getInstance2A() { encoder.encode(instance2) }
    E getInstance2B() { encoder.encode(instance2) }
    E getInstance2C() { encoder.encode(instance2) }

    def 'encoding and decoding is symmetric'() {

        expect:
            instance1A.decode() == instance1
            instance1B.decode() == instance1
            instance1C.decode() == instance1

        and:
            encoder.encode(instance1A.decode()) == instance1A
            encoder.encode(instance1B.decode()) == instance1A
            encoder.encode(instance1C.decode()) == instance1A

        and:
            encoder.encode(instance1A.decode()).decode() == instance1
            encoder.encode(instance1B.decode()).decode() == instance1
            encoder.encode(instance1C.decode()).decode() == instance1

        and:
            instance1A.decode() != instance2
            instance1B.decode() != instance2
            instance1C.decode() != instance2

        and:
            instance2A.decode() == instance2
            instance2B.decode() == instance2
            instance2C.decode() == instance2

        and:
            instance2A.decode() != instance1
            instance2B.decode() != instance1
            instance2C.decode() != instance1
    }

    def 'encoding and decoding is symmetric using raw'() {

        expect:
            encoder.of(instance1A.raw()) == encoder.encode(instance1)
            encoder.of(instance1B.raw()) == encoder.encode(instance1)
            encoder.of(instance1C.raw()) == encoder.encode(instance1)

        and:
            encoder.encode(encoder.of(instance1A.raw()).decode()).decode() == instance1
            encoder.encode(encoder.of(instance1B.raw()).decode()).decode() == instance1
            encoder.encode(encoder.of(instance1C.raw()).decode()).decode() == instance1
    }
}
