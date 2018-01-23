package com.gorson.web.wiremock;

import com.github.tomakehurst.wiremock.client.WireMock;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;

public class MockServer {
    public static void main(String[] args) throws IOException {
        WireMock.configureFor(8001);
        WireMock.removeAllMappings();
        mock("/mock");
    }

    private static void mock(String url) throws IOException {
        ClassPathResource resource = new ClassPathResource("application.properties");
        String content = StringUtils.join(FileUtils.readLines(resource.getFile(), "UTF-8").toArray(), "\n");
        WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo(url))
                .willReturn(WireMock.aResponse()
                        .withBody(content)
                        .withStatus(200)));
    }
}
