package ch.corporateapi.shell.keytool.config;

import ch.corporateapi.shell.keytool.config.KeyStoreFactoryBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Config {

    @Bean
    @ConfigurationProperties(prefix = "keystore")
    KeyStoreFactoryBean keyStore() {
        return new KeyStoreFactoryBean();
    }
}
