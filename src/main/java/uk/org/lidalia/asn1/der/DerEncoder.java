package uk.org.lidalia.asn1.der;

import uk.org.lidalia.asn1.Asn1;
import uk.org.lidalia.asn1.Asn1Encoder;
import uk.org.lidalia.encoding.core.InvalidEncoding;
import uk.org.lidalia.lang.Bytes;

import java.math.BigInteger;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collector;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableMap;
import static java.util.Collections.unmodifiableSet;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;

public class DerEncoder implements Asn1Encoder<Bytes, Der> {

    private final Set<? extends SpecificDerEncoder> encoders = unmodifiableSet(new HashSet<>(asList(
            new DerIntegerEncoder(),
            new DerSequenceEncoder()
    )));

    private final Map<Integer, SpecificDerEncoder> encodersByDerType = index(encoders, SpecificDerEncoder::derType);

    private final Map<Class<?>, SpecificDerEncoder> encodersByJavaType = index(encoders, SpecificDerEncoder::jvmType);

    private static <K, V> Map<K, V> index(Collection<? extends V> collection, Function<V, K> keyFun) {
        Collector<V, ?, Map<K,V>> asMap = toMap(keyFun, identity());
        return unmodifiableMap(collection.stream().collect(asMap));
    }

    public static final DerEncoder der = new DerEncoder();

    private DerEncoder() {}

    @Override
    public Der encode(Asn1 asn1) {
        return new Der(doEncode(asn1), asn1);
    }

    private Bytes doEncode(Asn1 asn1) {
        SpecificDerEncoder specificDerEncoder = encodersByJavaType.get(asn1.getClass());
        Bytes value = specificDerEncoder.encode(asn1);
        return Bytes.of(asList(
                Bytes.of(specificDerEncoder.derType().byteValue()),
                calculateLengthBytes(value.size()),
                value
        ));
    }

    private Bytes calculateLengthBytes(int size) {
        if (size < 128) {
            return Bytes.of((byte) size);
        } else {
            Bytes lengthSize = Bytes.of(BigInteger.valueOf(size)).stripLeadingZeros();
            Bytes lengthSizeSize = Bytes.of((byte) (128 + lengthSize.size()));
            return Bytes.of(lengthSizeSize, lengthSize);
        }
    }

    @Override
    public Der of(Bytes encoded) throws InvalidEncoding {
        return new Der(encoded, doDecode(encoded));
    }

    private Asn1 doDecode(Bytes encoded) throws InvalidEncoding {
        byte tag = encoded.get(0);

        Bytes lengthBytes = getLengthBytes(encoded.drop(1));
        int valueStart = 1 + lengthBytes.size();
        int valueEnd = valueStart + getLength(lengthBytes);

        Bytes value = encoded.subList(valueStart, valueEnd);
        return encodersByDerType.get((int) tag).decode(value);
    }


    static int getLength(Bytes lengthBytes) {
        return lengthBytes.size() == 1 ? lengthBytes.get(0) : lengthBytes.drop(1).unsignedBigInteger().intValue();
    }

    static Bytes getLengthBytes(Bytes bytes) {

        byte i = bytes.get(0);

        // A single byte short length
        if ((i & ~0x7F) == 0)
            return bytes.take(1);

        int num = i & 0x7F;

        return bytes.subList(0, num + 1);
    }
}

