package io.quarkus.vault.runtime.config;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigItem;

@ConfigGroup
public class MutualTLSProviderConfig {

    public static final String DEFAULT_PKI_MOUNT = "pki";

    /**
     * PKI role to use to generate key/certificate pairs.
     *
     * @asciidoclet
     */
    @ConfigItem
    public String role;

    /**
     * Mount of the PKI secrets engine, defaults to `pki`.
     *
     * Not required unless your PKI secret engine is mounted at a custom mount path.
     *
     * @asciidoclet
     */
    @ConfigItem(defaultValue = DEFAULT_PKI_MOUNT)
    public String mount;

    /**
     * Common name for the generated certificate.
     *
     * @asciidoclet
     */
    @ConfigItem
    public String commonName;

    /**
     * SubjectAlternateName(s) for the generated certificate.
     *
     * @asciidoclet
     */
    @ConfigItem
    public Optional<List<String>> subjectAlternateNames;

    /**
     * TTL for generated client certificates.
     *
     * Generated certificates will always expire after the TTL duration.
     *
     * @asciidoclet
     */
    @ConfigItem
    public Optional<Duration> ttl;

    @Override
    public String toString() {
        return "CredentialsProviderConfig{" +
                "role='" + role + '\'' +
                ", mount='" + mount + '\'' +
                ", commonName='" + commonName + '\'' +
                ", ttl='" + ttl + '\'' +
                '}';
    }
}
