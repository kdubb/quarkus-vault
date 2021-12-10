package io.quarkus.vault.runtime;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.jboss.logging.Logger;

import io.quarkus.mtls.MutualTLSConfig;
import io.quarkus.mtls.MutualTLSProvider;
import io.quarkus.runtime.Startup;
import io.quarkus.vault.VaultException;
import io.quarkus.vault.VaultPKISecretEngine;
import io.quarkus.vault.VaultPKISecretEngineFactory;
import io.quarkus.vault.pki.CertificateData;
import io.quarkus.vault.pki.DataFormat;
import io.quarkus.vault.pki.GenerateCertificateOptions;
import io.quarkus.vault.pki.GeneratedCertificate;
import io.quarkus.vault.pki.PrivateKeyEncoding;
import io.quarkus.vault.runtime.config.MutualTLSProviderConfig;
import io.quarkus.vault.runtime.config.VaultBootstrapConfig;

@Startup
@Singleton
@Named("vault-mtls-provider")
public class VaultMutualTLSProvider implements MutualTLSProvider {

    @Inject
    Logger logger;

    @Inject
    VaultPKISecretEngineFactory vaultPKISecretEngineFactory;

    @Inject
    VaultConfigHolder vaultConfigHolder;

    private final ConcurrentHashMap<String, MutualTLSConfig> cache = new ConcurrentHashMap<>();
    private final ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();

    @PostConstruct
    void initialize() {
        for (Map.Entry<String, MutualTLSProviderConfig> entry : getConfig().mtlsProvider.entrySet()) {
            String providerName = entry.getKey();
            MutualTLSProviderConfig providerConfig = entry.getValue();
            cache(providerName, providerConfig);
        }
    }

    private void cache(String providerName, MutualTLSProviderConfig providerConfig) {
        try {
            MutualTLSConfig mtlsConfig = load(providerConfig);

            cache.put(providerName, mtlsConfig);

            Duration ttl = Duration.between(Instant.now(), mtlsConfig.getExpiresAt()).dividedBy(2);
            executorService.schedule(() -> cache(providerName, providerConfig), ttl.toSeconds(), SECONDS);

            logger.infof("Refreshing mTLS configuration named '%s' in %s", providerName, ttl);
        } catch (Exception e) {
            logger.errorf(e, "Unable to load mTLS configuration named '%s'", providerName);
        }
    }

    private MutualTLSConfig load(MutualTLSProviderConfig config) throws Exception {

        VaultPKISecretEngine pkiSecretEngine = vaultPKISecretEngineFactory.engine(config.mount);

        List<X509Certificate> caChain = new ArrayList<>();
        caChain.add(pkiSecretEngine.getCertificateAuthority().getCertificate());
        caChain.addAll(pkiSecretEngine.getCertificateAuthorityChain().getCertificates());

        GenerateCertificateOptions generateCertificateOptions = new GenerateCertificateOptions()
                .setFormat(DataFormat.PEM)
                .setPrivateKeyEncoding(PrivateKeyEncoding.PKCS8)
                .setSubjectCommonName(config.commonName);
        config.subjectAlternateNames.ifPresent(generateCertificateOptions::setSubjectAlternativeNames);
        config.ttl.ifPresent(duration -> generateCertificateOptions.setTimeToLive(duration.toSeconds() + "s"));

        GeneratedCertificate clientCert = pkiSecretEngine.generateCertificate(config.role, generateCertificateOptions);

        List<X509Certificate> clientCertChain = new ArrayList<>();
        clientCertChain.add(clientCert.certificate.getCertificate());
        if (clientCert.caChain != null) {
            for (CertificateData cert : clientCert.caChain) {
                clientCertChain.add(cert.getCertificate());
            }
        } else {
            clientCertChain.add(clientCert.issuingCA.getCertificate());
        }

        Instant expiresAt = clientCert.certificate.getCertificate().getNotAfter().toInstant();

        PrivateKey privateKey = KeyFactory.getInstance(clientCert.privateKeyType.name())
                .generatePrivate(clientCert.privateKey.getKeySpec());

        return new MutualTLSConfig(clientCertChain, privateKey, caChain, expiresAt);
    }

    @Override
    public MutualTLSConfig getConfig(String mutualTLSProviderName) {
        return cache.get(mutualTLSProviderName);
    }

    private VaultBootstrapConfig getConfig() {
        VaultBootstrapConfig config = vaultConfigHolder.getVaultBootstrapConfig();
        if (config == null) {
            throw new VaultException(
                    "missing vault configuration required for mutual TLS providers");
        }
        return config;
    }
}
