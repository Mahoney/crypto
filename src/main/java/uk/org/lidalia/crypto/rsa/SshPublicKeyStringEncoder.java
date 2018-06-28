package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.ComposedEncoder;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import static java.util.regex.Pattern.DOTALL;
import static java.util.regex.Pattern.compile;
import static uk.org.lidalia.crypto.rsa.SshPublicKeyEncoder.sshPublicKey;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class SshPublicKeyStringEncoder implements Encoder<RsaPublicKey, String, SshPublicKeyString> {

    public static final SshPublicKeyStringEncoder sshPublicKeyString = new SshPublicKeyStringEncoder();

    @Override
    public SshPublicKeyString of(String encoded) throws InvalidEncoding {
        return new SshPublicKeyString(encoded, delegate.of(encoded).decode());
    }

    private static final ComposedEncoder<RsaPublicKey, Bytes, String> delegate = new ComposedEncoder<>(
            sshPublicKey,
            new Base64StringFormatEncoder(compile("^ssh-rsa (?<base64Block>[^ ]*)( .*)?\\n?$", DOTALL))
    );

    @Override
    public SshPublicKeyString encode(RsaPublicKey rsaPublicKey) {
        return new SshPublicKeyString(
                "ssh-rsa " + sshPublicKey.encode(rsaPublicKey).raw().encode(base64),
                rsaPublicKey
        );
    }
}
