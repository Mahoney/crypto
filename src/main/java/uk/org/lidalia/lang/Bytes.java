package uk.org.lidalia.lang;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;

public final class Bytes extends AbstractList<Byte> {

    public static Bytes of(byte[] bytes) {
        return new Bytes(Arrays.copyOf(bytes, bytes.length), 0, bytes.length);
    }

    public static Bytes of(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        copy(in, out);
        return uncopied(out.toByteArray());
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
        return uncopied(text.getBytes(charset));
    }

    public static Bytes of(String text) {
        return of(text, UTF_8);
    }

    public static Bytes of(BigInteger bigInteger) {
        return uncopied(bigInteger.toByteArray());
    }

    public static Bytes of(byte b) {
        return uncopied(new byte[] { b });
    }

    public static Bytes of(int integer) {
        return uncopied(ByteBuffer.allocate(4).putInt(integer).array());
    }

    private static final Bytes empty = Bytes.of(new byte[0]);

    public static Bytes empty() {
        return empty;
    }

    public static Bytes of(Bytes... elements) {
        return of(asList(elements));
    }

    // TODO this could be more efficient with no copying by storing the List<Bytes> as the
    // state of the Bytes object and doing the maths to haul data out of them as needed
    public static Bytes of(List<Bytes> elements) {
        int length = elements.stream().mapToInt(Bytes::size).sum();
        byte[] bytes = new byte[length];
        int offset = 0;
        for (Bytes element : elements) {
            System.arraycopy(element.array(), 0, bytes, offset, element.size());
            offset += element.size();
        }
        return uncopied(bytes);
    }

    private static Bytes uncopied(byte[] bytes) {
        return new Bytes(bytes, 0, bytes.length);
    }

    private static final SecureRandom secureRandom = new SecureRandom();

    public static Bytes random() {
        return random(secureRandom.nextInt(1024));
    }

    public static Bytes random(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return uncopied(bytes);
    }

    private final byte[] bytes;
    private final int fromIndex;
    private final int toIndex;

    private Bytes(byte[] bytes, int fromIndex, int toIndex) {
        this.bytes = Objects.requireNonNull(bytes);
        this.fromIndex = fromIndex;
        this.toIndex = toIndex;
    }

    public byte[] array() {
        return Arrays.copyOfRange(bytes, fromIndex, toIndex);
    }

    public String string(Charset charset) {
        return new String(bytes, fromIndex, size(), charset);
    }

    public String string() {
        return string(UTF_8);
    }

    public InputStream inputStream() {
        return new ByteArrayInputStream(bytes, fromIndex, size());
    }

    // TODO should this throw if length is != 4?
    public int integer() {
        return ByteBuffer.wrap(bytes).getInt(fromIndex);
    }

    public BigInteger bigInteger() {
        return new BigInteger(array());
    }

    public BigInteger unsignedBigInteger() {
        return new BigInteger(1, array());
    }

    @Override
    public int size() {
        return toIndex - fromIndex;
    }

    @Override
    public Byte get(int index) {
        return bytes[fromIndex + index];
    }

    public Bytes take(int number) {
        return subList(0, number);
    }

    public Bytes drop(int number) {
        return subList(number, size());
    }

    public Pair<Bytes, Bytes> split(int index) {
        return new Pair<>(take(index), drop(index));
    }

    @Override
    public Bytes subList(int fromIndex, int toIndex) {
        if (fromIndex == toIndex) {
            return empty;
        } else if (fromIndex == 0 && toIndex == this.size()) {
            return this;
        } else {
            validate(fromIndex, toIndex);
            return new Bytes(bytes, this.fromIndex + fromIndex, this.fromIndex + toIndex);
        }
    }

    private void validate(int fromIndex, int toIndex) {
        if (fromIndex < 0) {
            throw new IndexOutOfBoundsException("fromIndex ["+fromIndex+"] must be >= 0");
        }
        if (fromIndex > toIndex) {
            throw new IllegalArgumentException("fromIndex ["+fromIndex+"] must be <= to toIndex ["+toIndex+"]");
        }
        int size = size();
        if (toIndex > size) {
            throw new IndexOutOfBoundsException("toIndex ["+toIndex+"] must be <= to size() ["+ size +"]");
        }
    }

    public Bytes stripLeadingZeros() {
        if (size() <= 1) return this;
        if (get(0) != 0) return this;
        for (int i = fromIndex; i < toIndex; i++) {
            if (i != 0) return new Bytes(bytes, i, toIndex);
        }
        return Bytes.of((byte) 0);
    }
}
