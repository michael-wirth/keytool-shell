package ch.corporateapi.shell.keytool.config;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Base64Utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

import static org.springframework.util.StringUtils.hasText;

public class KeyStoreFactoryBean implements FactoryBean<KeyStore> {
  private Resource location;
  private String base64;
  private char[] password;
  private String type = "PKCS12";
  private String providerClassName;
  private String providerName = "SUN";

  @Override
  public KeyStore getObject() {
    return getKeystore();
  }

  @Override
  public Class<?> getObjectType() {
    return KeyStore.class;
  }

  public Resource getLocation() {
    return this.location;
  }

  public void setLocation(Resource location) {
    this.location = location;
  }

  public String getBase64() {
    return this.base64;
  }

  public void setBase64(String base64) {
    this.base64 = base64;
  }

  public char[] getPassword() {
    return this.password.clone();
  }

  public void setPassword(char[] password) {
    this.password = password.clone();
  }

  public String getType() {
    return this.type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getProviderClassName() {
    return this.providerClassName;
  }

  public void setProviderClassName(String providerClassName) {
    this.providerClassName = providerClassName;
  }

  public String getProviderName() {
    return this.providerName;
  }

  public void setProviderName(String providerName) {
    this.providerName = providerName;
  }

  public boolean hasKeystore() {
    return this.location != null || hasText(this.base64);
  }

  public KeyStore getKeystore() {
    if (!hasKeystore()) {
      return null;
    }

    try {
      registerSecurityProvider();
      KeyStore keyStore = instantiateKeystore();
      keyStore.load(getKeystoreInputStream(), this.password);
      return keyStore;
    } catch (GeneralSecurityException | IOException exception) {
      throw new SecurityException("Failed to create SSL keystore", exception);
    }
  }

  private void registerSecurityProvider() {
    if (hasText(this.providerClassName)) {
      try {
        Security.addProvider((Provider) Class.forName(this.providerClassName).getDeclaredConstructor().newInstance());
      } catch (ReflectiveOperationException exception) {
        throw new IllegalStateException("Failed to register security provider: " + this.providerClassName, exception);
      }
    }
  }

  private KeyStore instantiateKeystore() throws KeyStoreException, NoSuchProviderException {
    if (hasText(this.providerName)) {
      return KeyStore.getInstance(this.type, this.providerName);
    } else {
      return KeyStore.getInstance(this.type);
    }
  }

  private InputStream getKeystoreInputStream() throws IOException {
    if (this.location != null) {
      return this.location.getInputStream();
    }
    if (hasText(this.base64)) {
      return new ByteArrayInputStream(Base64Utils.decodeFromString(this.base64));
    }
    throw new IllegalStateException("Neither keystore.location nor keystore.base64 is defined.");
  }
}
