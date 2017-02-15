package uk.org.lidalia.asn1;

import java.util.ArrayList;
import java.util.List;

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

}
