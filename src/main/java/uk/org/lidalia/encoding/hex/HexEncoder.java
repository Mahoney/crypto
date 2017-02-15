package uk.org.lidalia.encoding.hex;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.ByteEncoder;

public class HexEncoder implements ByteEncoder<Hex> {

    public static final HexEncoder hex = new HexEncoder();

    private HexEncoder() {}

    @Override
    public Hex of(String encoded) throws NotAHexEncodedString {
        return new Hex(encoded);
    }

    @Override
    public Hex encode(Bytes decoded) {
        return new Hex(decoded);
    }
}
