package uk.org.lidalia.encoding.bytes;

import uk.org.lidalia.encoding.core.Encoded;
import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.lang.Bytes;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface ByteEncoder<T extends Encoded<Bytes, String>> extends Encoder<Bytes, String, T> {

    default T encode(byte[] decoded) {
        return encode(Bytes.of(decoded));
    }

    default T encode(String decoded) {
        return encode(decoded, UTF_8);
    }

    default T encode(String decoded, Charset charset) {
        return encode(Bytes.of(decoded, charset));
    }
}
