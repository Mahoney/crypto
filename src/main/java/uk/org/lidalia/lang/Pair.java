package uk.org.lidalia.lang;

import java.util.Objects;

import static java.util.Objects.requireNonNull;

public final class Pair<A, B> {

    public final A first;
    public final B second;

    public Pair(A first, B second) {
        this.first = requireNonNull(first);
        this.second = requireNonNull(second);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Pair<?, ?> pair = (Pair<?, ?>) o;
        return Objects.equals(first, pair.first) &&
                Objects.equals(second, pair.second);
    }

    @Override
    public int hashCode() {
        return Objects.hash(first, second);
    }
}
