package io.quarkus.vault.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;

import org.junit.jupiter.api.Test;

import io.quarkus.vault.client.test.Random;
import io.quarkus.vault.client.test.VaultClientTest;
import io.quarkus.vault.client.test.VaultClientTest.EngineMount;

@VaultClientTest({
        @EngineMount(engine = "kv", path = "kv-v1"),
})
public class VaultSecretsKV1Test {

    @Test
    void testUpdateRead(VaultClient client, @Random String path) {

        var kvApi = client.secrets().kv1("kv-v1");

        kvApi.update(path, Map.of("greeting", "hello", "subject", "world"))
                .await().indefinitely();

        var readResult = kvApi.read(path)
                .await().indefinitely();

        var data = readResult.data;

        assertThat(data).isNotNull()
                .hasSize(2)
                .containsEntry("greeting", "hello")
                .containsEntry("subject", "world");
    }

    @Test
    void testList(VaultClient client, @Random String path) {

        var kvApi = client.secrets().kv1("kv-v1");

        kvApi.update(path + "/test1", Map.of("key1", "val1", "key2", "val2"))
                .await().indefinitely();
        kvApi.update(path + "/test2", Map.of("key1", "val1", "key2", "val2"))
                .await().indefinitely();

        var listResult = kvApi.list(path + "/")
                .await().indefinitely();

        var data = listResult.data;

        assertThat(data).isNotNull();
        assertThat(data.keys).isNotNull()
                .contains("test1", "test2");
    }

    @Test
    void testListRoot(VaultClient client, @Random String path) {

        var kvApi = client.secrets().kv1("kv-v1");

        kvApi.update(path, Map.of("key1", "val1", "key2", "val2"))
                .await().indefinitely();

        var listResult = kvApi.list()
                .await().indefinitely();

        var data = listResult.data;

        assertThat(data).isNotNull();
        assertThat(data.keys).isNotNull()
                .contains(path);
    }

    @Test
    void testDelete(VaultClient client, @Random String path) {

        var kvApi = client.secrets().kv1("kv-v1");

        kvApi.update(path, Map.of("test", "some-value"))
                .await().indefinitely();

        // Validate update
        var data = kvApi.read(path)
                .await().indefinitely();

        assertThat(data).isNotNull();
        assertThat(data.data).isNotNull().containsEntry("test", "some-value");

        // Delete and validate

        kvApi.delete(path)
                .await().indefinitely();

        assertThrows(VaultClientException.class, () -> kvApi.read(path).await().indefinitely());
    }

}