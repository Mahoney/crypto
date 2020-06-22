package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.encoding.core.InvalidEncoding;
import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.lang.Pair;

import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;

public class SshPublicKeyEncoder implements Encoder<RsaPublicKey, Bytes, SshPublicKey> {

    public static final SshPublicKeyEncoder sshPublicKey = new SshPublicKeyEncoder();

    @Override
    public SshPublicKey of(Bytes encoded) throws InvalidEncoding {
        return new SshPublicKey(encoded, doDecode(encoded));
    }

    private static RsaPublicKey doDecode(Bytes encoded) throws InvalidEncoding {
        try {
            List<Bytes> dataElements = parse(encoded);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(
                    dataElements.get(2).bigInteger(),
                    dataElements.get(1).bigInteger()
            );
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

    @Override
    public SshPublicKey encode(RsaPublicKey rsaPublicKey) {
        return new SshPublicKey(doEncode(rsaPublicKey), rsaPublicKey);
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
}
