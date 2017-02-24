package uk.org.lidalia.asn1;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.InvalidEncoding;
import uk.org.lidalia.lang.Pair;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static java.util.stream.Collectors.toList;
import static uk.org.lidalia.asn1.DerEncoder.der;

class DerSequenceEncoder implements SpecificDerEncoder {

    @Override
    public Class jvmType() {
        return Asn1Sequence.class;
    }

    public Integer derType() {
        return 0x30;
    }

    @Override
    public Asn1Sequence decode(Bytes bytes) throws InvalidEncoding {
        List<Bytes> parse = parse(bytes);
        List<Asn1> entries = new ArrayList<>(parse.size());
        for (Bytes b: parse) {
            entries.add(der.of(b).decode());
        }
        return Asn1Sequence.of(entries);
    }

    private static List<Bytes> parse(Bytes bytes) {
        return parse(new LinkedList<>(), bytes);
    }

    private static List<Bytes> parse(List<Bytes> accumulator, Bytes bytes) {
        if (bytes.isEmpty()) {
            return accumulator;
        } else {
            Bytes lengthBytes = getLengthBytes(bytes.drop(1));
            int length = getLength(lengthBytes);
            int valueEnd = 1 + lengthBytes.size() + length;

            Pair<Bytes, Bytes> entryAndRemainder = bytes.split(valueEnd);
            accumulator.add(entryAndRemainder.first);
            return parse(accumulator, entryAndRemainder.second);
        }
    }

    private static int getLength(Bytes lengthBytes) {
        return lengthBytes.size() == 1 ? lengthBytes.get(0) : lengthBytes.drop(1).bigInteger().intValue();
    }

    private static Bytes getLengthBytes(Bytes bytes) {

        byte i = bytes.get(0);

        // A single byte short length
        if ((i & ~0x7F) == 0)
            return bytes.take(1);

        int num = i & 0x7F;

        return bytes.subList(0, num + 1);
    }

    @Override
    public Bytes encode(Asn1 asn1) {
        Asn1Sequence asn1Sequence = asn1.sequence();
        return Bytes.of(
                asn1Sequence.elements().stream()
                .map(element -> der.encode(element).raw())
                .collect(toList())
        );
    }
}
