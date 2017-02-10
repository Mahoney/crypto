package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Specification
import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey
import uk.org.lidalia.encoding.Bytes

import java.nio.file.Path

import static java.nio.file.Files.createTempDirectory

class RsaPrivateKeySerializationTests extends Specification {

    private static boolean sshInstalled() {
        'which ssh-keygen'.execute().waitFor() == 0
    }

//    @IgnoreIf({ !sshInstalled() })
    def 'a message encrypted by openssl using an ssh-keygen generated RSA keypair can be decrypted using the crypto API'() {

        given:
            def privateKeyFile = sshKeygen(tmpDir).first

        when:
            def encryptedBytes = openSslEncrypt(message, publicKeyPemFile(privateKeyFile))

        then:
            RsaPrivateCrtKey.fromFile(privateKeyFile).decrypt(encryptedBytes).string() == message

        cleanup:
            tmpDir.toFile().deleteOnExit()

        where:
            tmpDir = createTempDirectory('rsa-tests')
            message = RandomStringUtils.random(100).replaceAll("'", '')

    }

    private static Bytes openSslEncrypt(String message, Path publicKey) {
        resultOf(proc("echo -n '${message}'") | proc("openssl rsautl -encrypt -pubin -inkey $publicKey"))
    }

    private static Tuple2<Path, Path> sshKeygen(Path tmpDir) {
        def privateKeyFile = tmpDir.resolve('id_rsa')
        def publicKeyFile = tmpDir.resolve('id_rsa.pub')
        resultOf("ssh-keygen -t rsa -b 4096 -N '' -f $privateKeyFile")
        new Tuple2<>(privateKeyFile, publicKeyFile)
    }

    private static Path publicKeyPemFile(Path privateKeyFile) {
        def publicKeyPemFile = privateKeyFile.parent.resolve('id_rsa.pub.pem')
        resultOf("openssl rsa -in $privateKeyFile -pubout > $publicKeyPemFile")
        publicKeyPemFile
    }

    private static Process proc(String procStr) {
        ['/bin/bash', '-c', procStr].execute()
    }

    private static Bytes resultOf(String procStr) {
        resultOf(proc(procStr))
    }

    private static Bytes resultOf(Process process) {
        def result = Bytes.of(process.inputStream)
        def error = process.errorStream.text
        def status = process.waitFor()
        if (status != 0) {
            throw new Exception("Process $process failed with status $status, error: $error, result: $result")
        }
        result
    }
}
