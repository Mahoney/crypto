package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public final class EncryptedBytes<A extends CipherAlgorithm<A>> {

    private final Bytes bytes;
    private final Cipher<A> cipher;

    public static <A extends CipherAlgorithm<A>> EncryptedBytes<A> of(
        byte[] bytes,
        Cipher<A> cipher
    ) {
        return of(Bytes.of(bytes), cipher);
    }

    public static <A extends CipherAlgorithm<A>> EncryptedBytes<A> of(
        Bytes bytes,
        Cipher<A> cipher
    ) {
        return new EncryptedBytes<>(bytes, cipher);
    }

    private EncryptedBytes(Bytes bytes, Cipher<A> cipher) {
        this.bytes = requireNonNull(bytes);
        this.cipher = requireNonNull(cipher);
    }

    public Bytes bytes() {
        return bytes;
    }

    public Cipher<A> cipher() {
        return cipher;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        @SuppressWarnings("rawtypes") EncryptedBytes that = (EncryptedBytes) o;
        return Objects.equals(this.bytes, that.bytes) && Objects.equals(this.cipher, that.cipher);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bytes, cipher);
    }

    @Override
    public String toString() {
        return base64.encode(bytes).raw();
    }
}
