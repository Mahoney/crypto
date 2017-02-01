package uk.org.lidalia.encoding;

import uk.org.lidalia.encoding.base64.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.AbstractList;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Bytes extends AbstractList<Byte> {

    public static Bytes of(byte[] bytes) {
        return new Bytes(bytes);
    }

    public static Bytes of(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copy(in, out);
        return of(out.toByteArray());
    }

    private static final int BUF_SIZE = 0x1000; // 4K

    private static void copy(InputStream from, OutputStream to)
            throws IOException {
        byte[] buf = new byte[BUF_SIZE];
        while (true) {
            int r = from.read(buf);
            if (r == -1) {
                break;
            }
            to.write(buf, 0, r);
        }
    }

    public static Bytes of(String text, Charset charset) {
        return of(text.getBytes(charset));
    }

    public static Bytes of(String text) {
        return of(text, UTF_8);
    }

    private final byte[] bytes;

    protected Bytes(byte[] bytes) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
    }

    public byte[] array() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    public String string(Charset charset) {
        return new String(bytes, charset);
    }

    public String string() {
        return string(UTF_8);
    }

    public InputStream inputStream() {
        return new ByteArrayInputStream(bytes);
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
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Bytes)) return false;
        Bytes bytes1 = (Bytes) o;
        return Arrays.equals(bytes, bytes1.bytes);
    }

    @Override
    public final int hashCode() {
        return Arrays.hashCode(bytes);
    }
}
