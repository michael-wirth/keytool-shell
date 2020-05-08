package ch.corporateapi.shell.keytool;

import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.shell.standard.ShellOption.NULL;

@ShellComponent
public class ListCommand {

    private final KeyStore keyStore;

    public ListCommand(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @ShellMethod("List all keys and certificate.")
    public List<String> list(
            @ShellOption(defaultValue = NULL) String alias,
            @ShellOption boolean v) throws KeyStoreException {
        if (alias != null) {
            return List.of(format(alias));
        }
        return Collections.list(keyStore.aliases()).stream()
                .map(this::format).collect(Collectors.toList());
    }

    private String format(String alias) {
        try {
            return String.format("%s: %s, %s, %s",
                    alias,
                    entryType(alias),
                    keyStore.getCertificate(alias).getPublicKey().getAlgorithm(),
                    certDetails(alias)
            );
        } catch (KeyStoreException e) {
            return alias;
        }
    }

    private Object certDetails(String alias) {
        try {
            X509Certificate certificate = (X509Certificate) this.keyStore.getCertificate(alias);
            return String.format("sub: '%s', iss: '%s'", certificate.getSubjectX500Principal(), certificate.getIssuerX500Principal());
        } catch (KeyStoreException e) {
            return "n/a";
        }
    }

    private String entryType(String alias) throws KeyStoreException {
        return keyStore.isKeyEntry(alias) ? keyType(alias) :
                keyStore.isCertificateEntry(alias) ? "cert" : "n/a";
    }

    private String keyType(String alias) throws KeyStoreException {
        return keyStore.entryInstanceOf(alias, KeyStore.SecretKeyEntry.class) ? "SecretKeyEntry" : keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class) ? "PrivateKeyEntry" : "n/a";
    }
}
