package uk.org.lidalia.lang

import uk.org.lidalia.EqualsAndHashcodeTests

class PairEqualsAndHashCodeTests extends EqualsAndHashcodeTests<Pair<Integer, Integer>> {

    Pair<Integer, Integer> instance1A = new Pair<>(1, 2)
    Pair<Integer, Integer> instance1B = new Pair<>(1, 2)
    Pair<Integer, Integer> instance1C = new Pair<>(1, 2)

    Pair<Integer, Integer> instance2A = new Pair<>(2, 1)
    Pair<Integer, Integer> instance2B = new Pair<>(2, 1)
    Pair<Integer, Integer> instance2C = new Pair<>(2, 1)
}
