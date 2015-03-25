package uk.org.lidalia.crypto.rsa;

class RequiredAlgorithmNotPresent extends Error {
    RequiredAlgorithmNotPresent(String algorithm, Throwable cause) {
        super(algorithm + " is a required algorithm!", cause);
    }
}
