package uk.org.lidalia.crypto;

import uk.org.lidalia.lang.Bytes;

import java.util.Objects;

import static java.util.Objects.requireNonNull;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public final class EncryptedBytes<
    Encrypt extends EncryptKey<Encrypt, Decrypt>,
    Decrypt extends DecryptKey<Encrypt, Decrypt>
> {

    private final Bytes bytes;
    private final Cipher<Encrypt, Decrypt> cipher;

    public static <
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
    > EncryptedBytes<Encrypt, Decrypt> of(
        byte[] bytes,
        Cipher<Encrypt, Decrypt> cipher
    ) {
        return of(Bytes.of(bytes), cipher);
    }

    public static <
        Encrypt extends EncryptKey<Encrypt, Decrypt>,
        Decrypt extends DecryptKey<Encrypt, Decrypt>
    > EncryptedBytes<Encrypt, Decrypt> of(
        Bytes bytes,
        Cipher<Encrypt, Decrypt> cipher
    ) {
        return new EncryptedBytes<>(bytes, cipher);
    }

    private EncryptedBytes(
        Bytes bytes,
        Cipher<Encrypt, Decrypt> cipher
    ) {
        this.bytes = requireNonNull(bytes);
        this.cipher = requireNonNull(cipher);
    }

    public Bytes bytes() {
        return bytes;
    }

    public Cipher<Encrypt, Decrypt> cipher() {
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
