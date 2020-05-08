package ch.corporateapi.shell.keytool;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.Set;

public class GenKeyPairCommand {

    private final KeyStore keyStore;

    public GenKeyPairCommand(KeyStore keyStore) {
        this.keyStore = keyStore;
        Provider bouncyCastleProvider = new BouncyCastleProvider();
        Security.addProvider(bouncyCastleProvider);
    }

    String getKeyPair(String alias, String dname, String keyalg, int keysize, int validity, Set<String> san, char[] keyPassword)
            throws Exception {

        String providerName = getKeyPairGeneratorProviderName();
        KeyPair keyPair = generateKeyPair(keyalg, keysize, providerName);
        X509CertificateHolder certificateHolder = createCertificate(dname, validity, san, keyPair, providerName);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPassword, new Certificate[]{cert});

        File file = new File(alias + ".crt");
        String pemObject = writePEM(file, certificateHolder);
        return "Certificate: " + file.getAbsolutePath() + "\n\n" + pemObject;
    }

    private KeyPair generateKeyPair(String keyalg, int keysize, String providerName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyalg, providerName);
        if ("RSA".equals(keyalg)) {
            keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4));
        }
        if ("EC".equals(keyalg)) {
            keyPairGenerator.initialize(new ECGenParameterSpec("secp256k1"));
        }
        return keyPairGenerator.generateKeyPair();
    }

    private String getKeyPairGeneratorProviderName() {
        return keyStore.getProvider().getName().equals("SUN") ? "BC" : keyStore.getProvider().getName();
    }

    private X509CertificateHolder createCertificate(String dname, int validity, Set<String> san, KeyPair keyPair, String providerName)
            throws CertIOException, OperatorCreationException {
        LocalDate start = LocalDate.now();
        LocalDate end = start.plusDays(validity);
        BigInteger serial = serial();
        X500Name x500Name = new X500Name(dname);
        return new JcaX509v3CertificateBuilder(
                x500Name, serial, toDate(start), toDate(end), x500Name, keyPair.getPublic())
                .addExtension(Extension.basicConstraints, false, new BasicConstraints(true))
                .addExtension(Extension.keyUsage, false,
                        new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature))
                .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
                        new KeyPurposeId[]{
                                KeyPurposeId.id_kp_serverAuth,
                                KeyPurposeId.id_kp_clientAuth,
                                KeyPurposeId.id_kp_timeStamping}))
                .addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames(san))
                .build(getContentSigner(providerName, keyPair));
    }

    private DERSequence subjectAlternativeNames(Set<String> san) {
        ASN1Encodable[] ans1 = san.stream()
                .map(String::trim)
                .map(dname -> new GeneralName(GeneralName.dNSName, dname))
                .toArray(ASN1Encodable[]::new);
        return new DERSequence(ans1);
    }

    private Date toDate(LocalDate localDate) {
        return Date.from(localDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
    }

    private BigInteger serial() {
        BigInteger serialBase = BigInteger.valueOf(System.currentTimeMillis());
        return serialBase.add(BigInteger.valueOf(2));
    }

    private ContentSigner getContentSigner(String providerName, KeyPair keyPair) throws OperatorCreationException {
        return new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(providerName)
                .build(keyPair.getPrivate());
    }

    private String writePEM(File file, Object object) throws IOException {
        StringWriter stringWriter = new StringWriter();

        PemWriter pemWriter = new PemWriter(stringWriter);
        PemObjectGenerator objGen = new MiscPEMGenerator(object);
        pemWriter.writeObject(objGen);
        pemWriter.close();

        String pemObject = stringWriter.toString();
        FileWriter fileWriter = new FileWriter(file);
        fileWriter.write(pemObject);
        fileWriter.close();

        return pemObject;
    }
}
