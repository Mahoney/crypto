package uk.org.lidalia.asn1;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static java.util.Arrays.asList;

public class Asn1Sequence implements Asn1 {

    public static Asn1Sequence of(Asn1... elements) {
        return new Asn1Sequence(asList(elements));
    }

    public static Asn1Sequence of(List<Asn1> elements) {
        return new Asn1Sequence(elements);
    }

    private final List<Asn1> elements;

    private Asn1Sequence(List<Asn1> elements) {
        this.elements = new ArrayList<>(elements);
    }

    public Asn1 get(int i) {
        return elements.get(i);
    }

    public List<Asn1> elements() {
        return elements;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Asn1Sequence that = (Asn1Sequence) o;
        return Objects.equals(elements, that.elements);
    }

    @Override
    public int hashCode() {
        return Objects.hash(elements);
    }
}
