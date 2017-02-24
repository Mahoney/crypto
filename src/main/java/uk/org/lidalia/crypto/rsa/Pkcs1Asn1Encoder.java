package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.asn1.Asn1Integer;
import uk.org.lidalia.asn1.Asn1Sequence;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.math.BigInteger;
import java.security.spec.RSAPrivateCrtKeySpec;

public class Pkcs1Asn1Encoder implements Encoder<RsaPrivateKey, Asn1Sequence, Pkcs1Asn1> {

    public static final Pkcs1Asn1Encoder pkcs1Asn1 = new Pkcs1Asn1Encoder();

    private Pkcs1Asn1Encoder() {}

    @Override
    public Pkcs1Asn1 of(Asn1Sequence encodedKey) throws InvalidEncoding {
        return new Pkcs1Asn1(encodedKey, doDecode(encodedKey));
    }

    private static RsaPrivateKey doDecode(Asn1Sequence sequence) throws InvalidEncoding {

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
            throw new InvalidEncoding(sequence, "Unknown key format", e){};
        }
    }

    @Override
    public Pkcs1Asn1 encode(RsaPrivateKey decoded) {
        return new Pkcs1Asn1(doEncode(decoded), decoded);
    }

    private static Asn1Sequence doEncode(RsaPrivateKey key) {

        return Asn1Sequence.of(
                Asn1Integer.of(BigInteger.ZERO),
                Asn1Integer.of(key.getModulus()),
                Asn1Integer.of(key.getPublicExponent()),
                Asn1Integer.of(key.getPrivateExponent()),
                Asn1Integer.of(key.getPrimeP()),
                Asn1Integer.of(key.getPrimeQ()),
                Asn1Integer.of(key.getPrimeExponentP()),
                Asn1Integer.of(key.getPrimeExponentQ()),
                Asn1Integer.of(key.getCrtCoefficient())
        );
    }
}
