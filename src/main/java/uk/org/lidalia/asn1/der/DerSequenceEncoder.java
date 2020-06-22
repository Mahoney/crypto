package uk.org.lidalia.asn1.der;

import uk.org.lidalia.asn1.Asn1;
import uk.org.lidalia.asn1.Asn1Sequence;
import uk.org.lidalia.encoding.core.InvalidEncoding;
import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.lang.Pair;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static java.util.stream.Collectors.toList;
import static uk.org.lidalia.asn1.der.DerEncoder.getLength;
import static uk.org.lidalia.asn1.der.DerEncoder.getLengthBytes;

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
            entries.add(DerEncoder.der.of(b).decode());
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
            int valueStart = 1 + lengthBytes.size();
            int valueEnd = valueStart + getLength(lengthBytes);

            Pair<Bytes, Bytes> entryAndRemainder = bytes.split(valueEnd);
            accumulator.add(entryAndRemainder.first);
            return parse(accumulator, entryAndRemainder.second);
        }
    }

    @Override
    public Bytes encode(Asn1 asn1) {
        Asn1Sequence asn1Sequence = asn1.sequence();
        return Bytes.of(
                asn1Sequence.elements().stream()
                .map(element -> DerEncoder.der.encode(element).raw())
                .collect(toList())
        );
    }
}
