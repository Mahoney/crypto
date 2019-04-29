package uk.org.lidalia.crypto.core;

public interface SymmetricKey<
        S extends SymmetricKey<S> &
                  EncryptKey<S, S> &
                  DecryptKey<S, S>> extends EncryptKey<S, S>, DecryptKey<S, S> {
}
