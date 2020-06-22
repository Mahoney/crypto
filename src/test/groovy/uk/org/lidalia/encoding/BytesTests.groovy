package uk.org.lidalia.encoding

import spock.lang.Specification
import uk.org.lidalia.lang.Bytes

import static java.nio.charset.StandardCharsets.US_ASCII

class BytesTests extends Specification {

    def 'subList returns a subList'() {

        expect:
            Bytes.of([0, 1, 2, 3, 4, 5] as byte[]).subList(1, 5) == Bytes.of([1, 2, 3, 4] as byte[])
            Bytes.of([0, 1, 2, 3, 4, 5] as byte[]).subList(1, 5).subList(1, 3) == Bytes.of([2, 3] as byte[])
            Bytes.of([0, 1, 2, 3, 4, 5] as byte[]).drop(2) == Bytes.of([2, 3, 4, 5] as byte[])
    }

    def 'methods on subList work as expected'() {

        given:
            def bytes = Bytes.of([0, 1, 2, 3, 4, 5] as byte[]).subList(1, 5).drop(0)
            def strBytes = Bytes.of("abcdefg", US_ASCII).drop(1).drop(1).subList(1, 4)

        expect:
            Bytes.of(bytes.inputStream()) == bytes
            bytes.size() == 4
            bytes[0] == 1 as byte
            bytes[3] == 4 as byte
            bytes.array() == [1, 2, 3, 4] as byte[]
            strBytes.string(US_ASCII) == "def"
    }

    def 'take works as expected'() {

        given:
            def bytes = Bytes.of([0, 1, 2, 3, 4, 5] as byte[])

        expect:
            bytes.take(4) == Bytes.of([0, 1, 2, 3] as byte[])
            bytes.take(4).take(2) == Bytes.of([0, 1] as byte[])
    }

    def 'subList with same indexes is empty'() {

        given:
            def bytes = Bytes.of([0, 1, 2, 3, 4, 5] as byte[])

        expect:
            bytes.subList(2, 2) == Bytes.empty()
    }

    def 'subList with indexes wrong way round'() {

        given:
            def bytes = Bytes.of([0, 1, 2, 3, 4, 5] as byte[])

        when:
            bytes.subList(2, 1)

        then:
            def e = thrown(IllegalArgumentException)
            e.message == 'fromIndex [2] must be <= to toIndex [1]'
    }

    def 'subList with from index out of range'() {

        given:
            def bytes = Bytes.of([0, 1, 2, 3, 4, 5] as byte[])

        when:
            bytes.subList(-1, 1)

        then:
            def e = thrown(IndexOutOfBoundsException)
            e.message == 'fromIndex [-1] must be >= 0'
    }

    def 'subList with to index out of range'() {

        given:
            def bytes = Bytes.of([0, 1, 2, 3, 4, 5] as byte[])

        when:
            bytes.subList(0, 7)

        then:
            def e = thrown(IndexOutOfBoundsException)
            e.message == 'toIndex [7] must be <= to size() [6]'
    }

    def 'take too many'() {

        given:
            def bytes = Bytes.of([0, 1, 2, 3, 4, 5] as byte[])

        when:
            bytes.take(7)

        then:
            def e = thrown(IndexOutOfBoundsException)
            e.message == 'toIndex [7] must be <= to size() [6]'
    }

    def 'drop too many'() {

        given:
            def bytes = Bytes.of([0, 1, 2, 3, 4, 5] as byte[])

        when:
            bytes.drop(7)

        then:
            def e = thrown(IllegalArgumentException)
            e.message == 'fromIndex [7] must be <= to toIndex [6]'
    }

    def 'split too many'() {

        given:
            def bytes = Bytes.of([0, 1, 2, 3, 4, 5] as byte[])

        when:
            bytes.split(7)

        then:
            def e = thrown(IndexOutOfBoundsException)
            e.message == 'toIndex [7] must be <= to size() [6]'
    }
}
