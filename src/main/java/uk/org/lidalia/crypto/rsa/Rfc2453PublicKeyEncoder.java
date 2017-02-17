package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;
import uk.org.lidalia.lang.Pair;

import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;

public class Rfc2453PublicKeyEncoder implements Encoder<RsaPublicKey, Bytes, Rfc2453PublicKey> {

    public static final Rfc2453PublicKeyEncoder rfc2453PublicKey = new Rfc2453PublicKeyEncoder();

    @Override
    public Rfc2453PublicKey of(Bytes encoded) throws InvalidEncoding {
        return new Rfc2453PublicKey(encoded, doDecode(encoded));
    }

    @Override
    public Rfc2453PublicKey encode(RsaPublicKey rsaPublicKey) {
        return new Rfc2453PublicKey(doEncode(rsaPublicKey), rsaPublicKey);
    }

    private static Bytes doEncode(RsaPublicKey rsaPublicKey) {
        return Bytes.of(withLengths(
                Bytes.of("ssh-rsa"),
                Bytes.of(rsaPublicKey.getPublicExponent()),
                Bytes.of(rsaPublicKey.getModulus())
        ));
    }

    private static List<Bytes> withLengths(Bytes... elements) {
        return stream(elements)
                .flatMap((element) -> Stream.of(Bytes.of(element.size()), element))
                .collect(toList());
    }

    private static RsaPublicKey doDecode(Bytes encoded) throws InvalidEncoding {
        try {
            List<Bytes> dataElements = parse(encoded);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(dataElements.get(2).bigInteger(), dataElements.get(1).bigInteger());
            return RsaPublicKey.of(keySpec);
        } catch (Exception e) {
            throw new InvalidEncoding(encoded, "Unknown key format", e) {};
        }
    }

    private static List<Bytes> parse(Bytes keyBytes) {
        return parse(new ArrayList<>(), keyBytes);
    }

    private static List<Bytes> parse(List<Bytes> accumulator, Bytes bytes) {
        if (bytes.isEmpty()) {
            return accumulator;
        } else {
            Pair<Bytes, Bytes> lengthAndRemainder = bytes.split(4);
            Pair<Bytes, Bytes> dataAndRemainder = lengthAndRemainder.second.split(lengthAndRemainder.first.integer());
            accumulator.add(dataAndRemainder.first);
            return parse(accumulator, dataAndRemainder.second);
        }
    }
}
