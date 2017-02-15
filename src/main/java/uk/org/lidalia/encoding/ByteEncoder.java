package uk.org.lidalia.encoding;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface ByteEncoder<T extends EncodedBytes<T>> extends Encoder<Bytes, String, T> {

    T of(String encoded) throws NotAnEncodedString;

    T encode(Bytes decoded);

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
