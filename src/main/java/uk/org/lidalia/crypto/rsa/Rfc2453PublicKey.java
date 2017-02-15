package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;
import uk.org.lidalia.lang.Pair;

import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static uk.org.lidalia.encoding.base64.Base64.legalBase64Encoding;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Rfc2453PublicKey extends CachedEncodedBase<RsaPublicKey, String, Rfc2453PublicKey> implements Encoded<RsaPublicKey, String, Rfc2453PublicKey> {

    Rfc2453PublicKey(String bytes) throws InvalidEncoding {
        super(bytes, doDecode(bytes));
    }

    Rfc2453PublicKey(RsaPublicKey rsaPublicKey) {
        super(doEncode(rsaPublicKey), rsaPublicKey);
    }

    private static String doEncode(RsaPublicKey rsaPublicKey) {
        return "ssh-rsa " + Bytes.of(withLengths(
                Bytes.of("ssh-rsa"),
                Bytes.of(rsaPublicKey.getPublicExponent()),
                Bytes.of(rsaPublicKey.getModulus())
        )).encode();
    }

    private static List<Bytes> withLengths(Bytes... elements) {
        return stream(elements)
                .flatMap((element) -> Stream.of(Bytes.of(element.size()), element))
                .collect(toList());
    }

    private static Pattern keyRegex = Pattern.compile("^ssh-rsa (?<base64Key>"+legalBase64Encoding+")( .*)?\\n?$");

    private static RsaPublicKey doDecode(String encoded) throws InvalidEncoding {
        Matcher keyMatcher = keyRegex.matcher(encoded);

        if (keyMatcher.matches()) {

            String base64KeyStr = keyMatcher.group("base64Key");

            try {
                Bytes keyBytes = base64.of(base64KeyStr).decode();
                List<Bytes> dataElements = parse(keyBytes);
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(dataElements.get(2).bigInteger(), dataElements.get(1).bigInteger());
                return RsaPublicKey.fromKeySpec(keySpec);
            } catch (Exception e) {
                throw new InvalidEncoding("Unknown key format", encoded, e) {};
            }

        } else {
            throw new InvalidEncoding("Unknown key format", encoded, null) {};
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
    public Rfc2453PublicKeyEncoder encoder() {
        return Rfc2453PublicKeyEncoder.rfc2453PublicKey;
    }
}
