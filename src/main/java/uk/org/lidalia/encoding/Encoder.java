package uk.org.lidalia.encoding;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface Encoder<T extends Encoded<T>> {

    T of(String encoded);

    T encode(byte[] decoded);

    default T encode(String decoded) {
        return encode(decoded, UTF_8);
    }

    default T encode(String decoded, Charset charset) {
        return encode(decoded.getBytes(charset));
    }
}
