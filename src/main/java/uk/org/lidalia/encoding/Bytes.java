package uk.org.lidalia.encoding;

import uk.org.lidalia.encoding.base64.Base64;

import java.nio.charset.Charset;
import java.util.AbstractList;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Bytes extends AbstractList<Byte> {

    public static Bytes of(byte[] bytes) {
        return new Bytes(bytes);
    }

    public static Bytes of(String text, Charset charset) {
        return of(text.getBytes(charset));
    }

    public static Bytes of(String text) {
        return of(text, UTF_8);
    }

    private final byte[] bytes;

    public Bytes(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] asArray() {
        return bytes;
    }

    public String asString(Charset charset) {
        return new String(bytes, charset);
    }

    public String asString() {
        return asString(UTF_8);
    }

    public <T extends Encoded<T>> T encode(Encoder<T> encoder) {
        return encoder.encode(bytes);
    }

    public Base64 encode() {
        return encode(base64);
    }

    @Override
    public int size() {
        return bytes.length;
    }

    @Override
    public Byte get(int index) {
        return bytes[index];
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Bytes bytes1 = (Bytes) o;
        return Arrays.equals(bytes, bytes1.bytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
