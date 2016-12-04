package uk.org.lidalia.crypto;

interface SymmetricKey<
        S extends SymmetricKey<S> &
                  EncryptKey<S, S> &
                  DecryptKey<S, S>> extends EncryptKey<S, S>, DecryptKey<S, S> {
}
