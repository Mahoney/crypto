package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import static uk.org.lidalia.asn1.DerEncoder.der;
import static uk.org.lidalia.crypto.rsa.Pkcs1Asn1Encoder.pkcs1Asn1;

public class Pkcs1Encoder implements Encoder<RsaPrivateKey, Bytes, Pkcs1> {

    public static final Pkcs1Encoder pkcs1 = new Pkcs1Encoder();

    private Pkcs1Encoder() {}

    @Override
    public Pkcs1 of(Bytes encodedKey) throws InvalidEncoding {
        return new Pkcs1(encodedKey, doDecode(encodedKey));
    }

    private static RsaPrivateKey doDecode(Bytes keyBytes) throws InvalidEncoding {
        return pkcs1Asn1.of(der.of(keyBytes).decode().sequence()).decode();
    }

    @Override
    public Pkcs1 encode(RsaPrivateKey decoded) {
        return new Pkcs1(doEncode(decoded), decoded);
    }

    private Bytes doEncode(RsaPrivateKey decoded) {
        return pkcs1Asn1.encode(decoded).raw().encode().raw();
    }
}
