package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static uk.org.lidalia.crypto.rsa.Pkcs1Encoder.pkcs1;
import static uk.org.lidalia.crypto.rsa.PrivateKeyReader.getRsaPrivateKeySpec;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Pkcs1 implements Encoded<RsaPrivateKey, String, Pkcs1> {

    private final String raw;
    private final RsaPrivateKey key;

    Pkcs1(String raw) throws InvalidEncoding {
        this.raw = raw;
        this.key = doDecode(raw);
    }

    private static Pattern keyRegex = Pattern.compile(".*-----BEGIN RSA PRIVATE KEY-----(?<base64Key>.*)-----END RSA PRIVATE KEY-----.*", Pattern.DOTALL);

    private static RsaPrivateKey doDecode(String raw) throws InvalidEncoding {

        Matcher keyMatcher = keyRegex.matcher(raw);

        if (keyMatcher.matches()) {

            String base64KeyStr = keyMatcher.group("base64Key").replaceAll("\\s+", "");
            Bytes keyBytes = base64.of(base64KeyStr).decode();

            try {
                return RsaPrivateKey.fromKeySpec(getRsaPrivateKeySpec(keyBytes.array()));
            } catch (IOException | InvalidKeySpecException e) {
                throw new InvalidEncoding(raw, "Unknown key format", e) {};
            }

        } else {
            throw new InvalidEncoding(raw, "Unknown key format", null) {};
        }
    }

    @Override
    public Pkcs1Encoder encoder() {
        return pkcs1;
    }

    @Override
    public RsaPrivateKey decode() {
        return key;
    }

    @Override
    public String raw() {
        return raw;
    }
}
