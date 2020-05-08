package ch.corporateapi.shell.keytool;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;
import org.springframework.util.StringUtils;

import java.security.KeyStore;
import java.util.List;
import java.util.Set;

@ShellComponent
public class KeyTool {

    private final KeyStore keyStore;
    private final char[] keyPassword;
    private final GenKeyPairCommand genKeyPairCommand;

    public KeyTool(KeyStore keyStore, @Value("${keystore.key-password}") char[] keyPassword) {
        this.keyStore = keyStore;
        this.keyPassword = keyPassword;
        this.genKeyPairCommand = new GenKeyPairCommand(keyStore);
    }

    @ShellMethod("Generates a key pair")
    public String genkeypair(
            @ShellOption(help = "alias name of the entry to process") String alias,
            @ShellOption(help = "distinguished name") String dname,
            @ShellOption(help = "key algorithm name", defaultValue = "RSA") String keyalg,
            @ShellOption(help = "key bit size", defaultValue = "4096") int keysize,
            @ShellOption(help = "validity number of days", defaultValue = "1096") int validity,
            @ShellOption(help = "subject alternative names") String san,
            @ShellOption boolean v) throws Exception {

        Set<String> sanSet = Set.of(StringUtils.tokenizeToStringArray(san, "|"));
        return this.genKeyPairCommand.getKeyPair(alias, dname, keyalg, keysize, validity, sanSet, keyPassword);
    }

    @ShellMethod("Deletes an entry")
    public void delete(
            @ShellOption(help = "alias name of the entry to process") String alias,
            @ShellOption boolean v) throws Exception {

        this.keyStore.deleteEntry(alias);
    }

}
