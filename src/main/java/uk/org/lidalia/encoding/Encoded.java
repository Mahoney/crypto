package uk.org.lidalia.encoding;

import java.nio.charset.Charset;

import static java.nio.charset.StandardCharsets.UTF_8;

public interface Encoded<T extends Encoded<T>> {

    Encoder<T> getEncoder();

    byte[] getDecoded();

    default String toDecodedString() {
        return toDecodedString(UTF_8);
    }

    default String toDecodedString(Charset charset) {
        return new String(getDecoded(), charset);
    }

}
