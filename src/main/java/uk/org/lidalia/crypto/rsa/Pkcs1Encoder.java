package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.asn1.Asn1Integer;
import uk.org.lidalia.asn1.Asn1Sequence;
import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.math.BigInteger;
import java.security.spec.RSAPrivateCrtKeySpec;

import static uk.org.lidalia.asn1.DerEncoder.der;

public class Pkcs1Encoder implements Encoder<RsaPrivateKey, Bytes, Pkcs1> {

    public static final Pkcs1Encoder pkcs1 = new Pkcs1Encoder();

    private Pkcs1Encoder() {}

    @Override
    public Pkcs1 of(Bytes encodedKey) throws InvalidEncoding {
        return new Pkcs1(encodedKey, doDecode(encodedKey));
    }

    private static RsaPrivateKey doDecode(Bytes keyBytes) throws InvalidEncoding {

        Asn1Sequence sequence = der.of(keyBytes).decode().sequence();

        try {
            BigInteger modulus = sequence.get(1).integer().value();
            BigInteger publicExp = sequence.get(2).integer().value();
            BigInteger privateExp = sequence.get(3).integer().value();
            BigInteger prime1 = sequence.get(4).integer().value();
            BigInteger prime2 = sequence.get(5).integer().value();
            BigInteger exp1 = sequence.get(6).integer().value();
            BigInteger exp2 = sequence.get(7).integer().value();
            BigInteger crtCoef = sequence.get(8).integer().value();

            return RsaPrivateKey.of(
                    new RSAPrivateCrtKeySpec(
                            modulus, publicExp, privateExp, prime1, prime2,
                            exp1, exp2, crtCoef
                    )
            );
        } catch (Exception e) {
            throw new InvalidEncoding(keyBytes, "Unknown key format", e){};
        }
    }

    @Override
    public Pkcs1 encode(RsaPrivateKey decoded) {
        return new Pkcs1(doEncode(decoded), decoded);
    }

    private Bytes doEncode(RsaPrivateKey decoded) {
        Asn1Sequence sequence = Asn1Sequence.of(
                Asn1Integer.of(BigInteger.ZERO),
                Asn1Integer.of(decoded.getModulus()),
                Asn1Integer.of(decoded.getPublicExponent()),
                Asn1Integer.of(decoded.getPrivateExponent()),
                Asn1Integer.of(decoded.getPrimeP()),
                Asn1Integer.of(decoded.getPrimeQ()),
                Asn1Integer.of(decoded.getPrimeExponentP()),
                Asn1Integer.of(decoded.getPrimeExponentQ()),
                Asn1Integer.of(decoded.getCrtCoefficient())
        );
        return sequence.encode().raw();
    }
}
