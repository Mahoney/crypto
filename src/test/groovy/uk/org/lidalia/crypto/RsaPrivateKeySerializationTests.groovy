package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Ignore
import spock.lang.IgnoreIf
import spock.lang.Specification
import uk.org.lidalia.crypto.rsa.RsaPrivateKey
import uk.org.lidalia.crypto.rsa.RsaPublicKey
import uk.org.lidalia.encoding.Bytes

import java.nio.file.Path

import static java.nio.file.Files.createTempDirectory
import static uk.org.lidalia.encoding.hex.HexEncoder.hex

@IgnoreIf({ 'which ssh-keygen'.execute().waitFor() > 0 })
class RsaPrivateKeySerializationTests extends Specification {

    static def tmpDir = createTempDirectory('rsa-tests')
    static { tmpDir.toFile().deleteOnExit() }
    static def keyFilePair = sshKeygen(tmpDir)
    static def privateKeyFile = keyFilePair.first
    static def publicKeyFile = keyFilePair.second
    static def privateKey = RsaPrivateKey.generate()
    static def publicKey = privateKey.publicKey()

    def 'exported public key is same as openssh converted one'() {

        given:
            def publicKeyPemFile = publicKeyPemFile(privateKeyFile)
            def importedPublicKey = RsaPublicKey.fromFile(publicKeyFile)

        expect:
            importedPublicKey.exportX509() == publicKeyPemFile.text

    }

    @Ignore('Not yet worked out how to export to PKCS8 format')
    def 'exported private key is same as ssh-keygen generated one'() {

        given:
            def importedPrivateKey = RsaPrivateKey.fromFile(privateKeyFile)

        expect:
            importedPrivateKey.export() == privateKeyFile.text

    }

    def 'can import ssh-keygen private key and decrypt message encrypted using openssl with it'() {

        given:
            def publicKeyPemFile = publicKeyPemFile(privateKeyFile)
            def privateKey = RsaPrivateKey.fromFile(privateKeyFile)

        when:
            def encryptedBytes = openSslEncrypt(message, publicKeyPemFile)

        then:
            privateKey.decrypt(encryptedBytes).string() == message

        where:
            message = RandomStringUtils.random(100).replaceAll("'", '')

    }

    def 'can import ssh-keygen public key, encrypt message with it and decrypt result with openssl'() {

        given:
            def publicKey = RsaPublicKey.fromFile(publicKeyFile)

        when:
            def encryptedBytes = publicKey.encrypt(message)

        then:
            openSslDecrypt(encryptedBytes, privateKeyFile) == message

        where:
            message = RandomStringUtils.random(100).replaceAll("'", '')

    }
    def 'can export private key and decrypt message with it'() {

        given:
            def exportedPrivateKeyFile = tmpDir.resolve('id_rsa_exported')
            exportedPrivateKeyFile << privateKey.export()

        when:
            def encryptedBytes = publicKey.encrypt(message)

        then:
            openSslDecrypt(encryptedBytes, exportedPrivateKeyFile) == message

        where:
            message = RandomStringUtils.random(50).replaceAll("'", '')

    }

    def 'can export public key, encrypt message with it and decrypt result'() {

        given:
            def exportedPublicKeyFile = tmpDir.resolve('id_rsa_exported.pub')
            exportedPublicKeyFile << publicKey.export()

        when:
            def encryptedBytes = openSslEncrypt(message, exportedPublicKeyFile)

        then:
            privateKey.decrypt(encryptedBytes).string() == message

        where:
            message = RandomStringUtils.random(50).replaceAll("'", '')

    }

    private static Bytes openSslEncrypt(String message, Path publicKey) {
        resultOf(proc("echo -n '${message}'") | proc("openssl rsautl -encrypt -pubin -inkey $publicKey"))
    }

    private static String openSslDecrypt(Bytes encrypted, Path privateKey) {
        resultOf(proc("echo -n -e '${hexCodes(encrypted)}'") | proc("openssl rsautl -decrypt -inkey $privateKey")).string()
    }

    private static String hexCodes(Bytes encrypted) {
        encrypted.encode(hex).toString().split(/(?<=\G.{2})/).collect { /\x$it/ }.join('')
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
