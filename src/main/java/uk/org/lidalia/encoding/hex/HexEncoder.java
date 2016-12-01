package uk.org.lidalia.encoding.hex;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;

public class HexEncoder implements Encoder<Hex> {

    public static HexEncoder hex = new HexEncoder();

    private HexEncoder() {}

    @Override
    public Hex of(String encoded) {
        return new Hex(encoded, this);
    }

    @Override
    public Hex encode(Bytes decoded) {

        byte[] decodedByes = decoded.asArray();

        final char[] chars = new char[decodedByes.length * 2];

        for (int i = 0; i < decodedByes.length; i++) {
            int nibble1 = (0xF0 & decodedByes[i]) >>> 4;
            int nibble2 = 0x0F & decodedByes[i];
            chars[i*2] = Character.forDigit(nibble1, 16);
            chars[i*2+1] = Character.forDigit(nibble2, 16);
        }

        return new Hex(new String(chars), this);
    }
}