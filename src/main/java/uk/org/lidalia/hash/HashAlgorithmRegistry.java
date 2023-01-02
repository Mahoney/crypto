package uk.org.lidalia.hash;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.unmodifiableMap;
import static java.util.Collections.unmodifiableSet;
import static java.util.Optional.ofNullable;

class HashAlgorithmRegistry {

    private static final Set<HashAlgorithm> registry = new LinkedHashSet<>();

    static Set<HashAlgorithm> values() {
        return unmodifiableSet(registry);
    }

    private static final Map<String, HashAlgorithm> valueMap = buildValueMap();

    static HashAlgorithm valueOf(String algName) {
        return ofNullable(
                valueMap.get(algName)
        ).orElseThrow(() ->
                new IllegalArgumentException("Unknown "+HashAlgorithmRegistry.class.getSimpleName()+": "+algName)
        );
    }

    static HashAlgorithm register(HashAlgorithm alg) {
        registry.add(alg);
        return alg;
    }

    private static Map<String, HashAlgorithm> buildValueMap() {
        Map<String, HashAlgorithm> values = new LinkedHashMap<>();
        for (HashAlgorithm algorithm : registry) {
            values.put(algorithm.toString(), algorithm);
        }
        return unmodifiableMap(values);
    }
}
