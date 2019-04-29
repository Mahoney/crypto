package uk.org.lidalia.crypto.core;

public class RequiredAlgorithmNotPresent extends Error {
    public RequiredAlgorithmNotPresent(String algorithm, Throwable cause) {
        super(algorithm + " is a required algorithm!", cause);
    }
}
