package uk.org.lidalia.asn1;

import java.math.BigInteger;
import java.util.Objects;

public class Asn1Integer implements Asn1 {

    public static Asn1Integer of(BigInteger integer) {
        return new Asn1Integer(integer);
    }

    private final BigInteger integer;

    private Asn1Integer(BigInteger integer) {
        this.integer = integer;
    }

    public BigInteger value() {
        return integer;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Asn1Integer that = (Asn1Integer) o;
        return Objects.equals(integer, that.integer);
    }

    @Override
    public int hashCode() {
        return Objects.hash(integer);
    }

    @Override
    public String toString() {
        return integer.toString();
    }
}
