package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.security.spec.InvalidKeySpecException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static uk.org.lidalia.crypto.rsa.Pkcs8Encoder.pkcs8;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Pkcs8 implements Encoded<RsaPrivateKey, String, Pkcs8> {

    private final String raw;
    private final RsaPrivateKey key;

    Pkcs8(String raw) throws InvalidEncoding {
        this(raw, doDecode(raw));
    }

    Pkcs8(RsaPrivateKey key) {
        this(doEncode(key), key);
    }

    private Pkcs8(String raw, RsaPrivateKey key) {
        this.raw = raw;
        this.key = key;
    }


    private static String doEncode(RsaPrivateKey decoded) {
        return "-----BEGIN PRIVATE KEY-----\n"+
                Bytes.of(decoded.getEncoded()).encode().toString().replaceAll("(.{64})", "$1\n")+
                "\n-----END PRIVATE KEY-----\n";
    }

    private static Pattern keyRegex = Pattern.compile(".*-----BEGIN PRIVATE KEY-----(?<base64Key>.*)-----END PRIVATE KEY-----.*", Pattern.DOTALL);

    private static RsaPrivateKey doDecode(String raw) throws InvalidEncoding {

        Matcher keyMatcher = keyRegex.matcher(raw);

        if (keyMatcher.matches()) {

            String base64KeyStr = keyMatcher.group("base64Key").replaceAll("\\s+", "");
            Bytes keyBytes = base64.of(base64KeyStr).decode();

            try {
                return RsaPrivateKey.fromEncoded(keyBytes);
            } catch (InvalidKeySpecException e) {
                throw new InvalidEncoding(raw, "Unknown key format", e) {};
            }

        } else {
            throw new InvalidEncoding(raw, "Unknown key format", null) {};
        }
    }

    @Override
    public Pkcs8Encoder encoder() {
        return pkcs8;
    }

    @Override
    public RsaPrivateKey decode() {
        return key;
    }

    @Override
    public String raw() {
        return raw;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Pkcs8 pkcs8 = (Pkcs8) o;
        return Objects.equals(raw, pkcs8.raw);
    }

    @Override
    public int hashCode() {
        return Objects.hash(raw);
    }

    @Override
    public String toString() {
        return raw();
    }
}
