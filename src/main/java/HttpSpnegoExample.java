import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;

public class HttpSpnegoExample {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("Usage: HttpSpnegoExample takes one argument [hostname] of the web server protected by kerberos.");
            System.exit(0);
        }
        String host = args[0];
        System.setProperty("java.security.krb5.conf", new File("krb5.ini").getCanonicalPath());
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        System.setProperty("java.security.auth.login.config", new File("login.conf").getCanonicalPath());

        String baseUrl = "http://" + host + ":81";
        String loginEntryName = "anotherentry";

        try (SpnegoAuth spnegoAuth = new SpnegoAuth(loginEntryName)) {
            BlockingQueue<String> fileNames = new LinkedBlockingDeque<>();
            fileNames.addAll(FileUtils.readLines(new File("filenames.txt"), "UTF-8"));

            ExecutorService executorService = Executors.newFixedThreadPool(5);
            List<Future> futures = new ArrayList<>();
            for (int i = 0; i < 5; ++i) {
                futures.add(executorService.submit(() -> {
                    try (CloseableHttpClient closeableHttpClient = HttpClients.createMinimal()) {
                        while (!fileNames.isEmpty()) {
                            String nextFilename = fileNames.poll(1000L, TimeUnit.MILLISECONDS);
                            if (StringUtils.isNotBlank(nextFilename)) {
                                String url = baseUrl + "/" + nextFilename;
                                String authorizationHeader = spnegoAuth.getAuthorizationHeader(url);
                                System.out.println("Next Authorization header: " + authorizationHeader);

                                HttpGet httpget = new HttpGet(url);
                                httpget.setHeader("Authorization", authorizationHeader);
                                try (CloseableHttpResponse closeableHttpResponse = closeableHttpClient.execute(httpget)) {
                                    FileUtils.copyInputStreamToFile(closeableHttpResponse.getEntity().getContent(), new File("files", nextFilename));
                                }
                            }
                        }
                    }
                    return true;
                }));
            }
            for (Future future : futures) {
                future.get();
            }
        }
    }
}
