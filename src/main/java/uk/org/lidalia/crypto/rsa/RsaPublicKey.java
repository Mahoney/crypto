package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.EncryptKey;
import uk.org.lidalia.crypto.PublicKey;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.base64.NotABase64EncodedString;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static java.nio.file.Files.newInputStream;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static uk.org.lidalia.crypto.rsa.PrivateKeyReader.getRsaPublicKeySpec;
import static uk.org.lidalia.crypto.rsa.Rsa.RSA;
import static uk.org.lidalia.encoding.base64.Base64.legalBase64Encoding;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public final class RsaPublicKey
        extends RsaKey<RSAPublicKey>
        implements RSAPublicKey, PublicKey<RsaPublicKey, RsaPrivateKey, RsaPrivateKey>,
        EncryptKey<RsaPublicKey, RsaPrivateKey> {

    public static RsaPublicKey fromEncoded(final Bytes publicKeyEncoded)
            throws InvalidKeySpecException {
        final X509EncodedKeySpec publicKeySpec
                = new X509EncodedKeySpec(publicKeyEncoded.array());
        return fromKeySpec(publicKeySpec);
    }

    public static RsaPublicKey fromKeySpec(final KeySpec publicKeySpec)
            throws InvalidKeySpecException {
        return RSA.publicKey(publicKeySpec);
    }

    public static RsaPublicKey from(final RSAPublicKey decorated) {
        return new RsaPublicKey(decorated);
    }

    private RsaPublicKey(final RSAPublicKey decorated) {
        super(decorated);
    }

    @Override
    public String export() {
        return exportX509();
    }

    public String exportX509() {
        return "-----BEGIN PUBLIC KEY-----\n"+
                Bytes.of(getEncoded()).encode().toString().replaceAll("(.{64})", "$1\n")+
                "\n-----END PUBLIC KEY-----\n";
    }

    public String exportOpenSsh() {
        return "ssh-rsa " + Bytes.of(withLengths(
                Bytes.of("ssh-rsa"),
                Bytes.of(getPublicExponent()),
                Bytes.of(getModulus())
        )).encode();
    }

    private static List<Bytes> withLengths(Bytes... elements) {
        return stream(elements)
                .flatMap((element) -> Stream.of(Bytes.of(element.size()), element))
                .collect(toList());
    }

    public static RsaPublicKey fromFile(Path path) throws IOException, InvalidKeySpecException, NotABase64EncodedString {
        try (InputStream in = newInputStream(path)) {
            return fromString(Bytes.of(in).string());
        }
    }

    private static Pattern keyRegex = Pattern.compile("^ssh-rsa (?<base64Key>"+legalBase64Encoding+")( .*)?\\n?$");

    public static RsaPublicKey fromString(String keyStr) throws NotABase64EncodedString, InvalidKeySpecException, IOException {

        Matcher keyMatcher = keyRegex.matcher(keyStr);

        if (keyMatcher.matches()) {

            String base64KeyStr = keyMatcher.group("base64Key");
            Bytes keyBytes = base64.of(base64KeyStr).decode();
            return fromKeySpec(getRsaPublicKeySpec(keyBytes));

        } else {
            throw new InvalidKeySpecException("Unknown key format");
        }
    }

    /**** REMAINING METHODS DELEGATE ****/

    @Override
    public BigInteger getPublicExponent() {
        return decorated.getPublicExponent();
    }
}
