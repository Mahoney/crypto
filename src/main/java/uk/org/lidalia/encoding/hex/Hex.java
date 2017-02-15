package uk.org.lidalia.encoding.hex;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.EncodedBytes;

import static uk.org.lidalia.encoding.hex.HexEncoder.hex;

public class Hex extends CachedEncodedBase<Bytes, String, Hex> implements EncodedBytes<Hex> {

    Hex(String encoded) throws NotAHexEncodedString {
        super(encoded, doDecode(encoded));
    }

    Hex(Bytes decoded) {
        super(doEncode(decoded), decoded);
    }

    private static Bytes doDecode(String encoded) throws NotAHexEncodedString {
        char[] chars = encoded.toCharArray();
        if (chars.length % 2 != 0) {
            throw NotAHexEncodedString.of(encoded);
        }
        byte[] decoded = new byte[chars.length / 2];

        for (int i = 0; i < decoded.length; i++) {
            int nibble1 = Character.digit(chars[i*2], 16);
            int nibble2 = Character.digit(chars[i*2+1], 16);
            if (nibble1 == -1 || nibble2 == -1) {
                throw NotAHexEncodedString.of(encoded);
            }
            decoded[i] = (byte) (nibble1*16+nibble2);
        }

        return Bytes.of(decoded);
    }

    private static String doEncode(Bytes decoded) {
        byte[] decodedByes = decoded.array();

        final char[] chars = new char[decodedByes.length * 2];

        for (int i = 0; i < decodedByes.length; i++) {
            int nibble1 = (0xF0 & decodedByes[i]) >>> 4;
            int nibble2 = 0x0F & decodedByes[i];
            chars[i*2] = Character.forDigit(nibble1, 16);
            chars[i*2+1] = Character.forDigit(nibble2, 16);
        }

        return new String(chars);
    }

    public HexEncoder encoder() {
        return hex;
    }
}
