package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.crypto.Base64StringFormatEncoder;
import uk.org.lidalia.encoding.core.ComposedEncoder;
import uk.org.lidalia.encoding.core.Encoder;
import uk.org.lidalia.encoding.core.InvalidEncoding;
import uk.org.lidalia.lang.Bytes;

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
                "ssh-rsa " + base64.encode(sshPublicKey.encode(rsaPublicKey).raw()),
                rsaPublicKey
        );
    }
}
