# dcp-tck

Technology Compatibility Kit for the Decentralized Claims Protocol

## 1. Overview

The Technology Compatibility Kit (TCK) for the Decentralized Claims Protocol (DCP) is a set of tests that asserts
compliance with
the [Decentralized Claims Protocol Specification](https://eclipse-dataspace-dcp.github.io/decentralized-claims-protocol/).

It consists of a series of tests for each of the subsections of the specification, i.e. Verifiable Presentation
Protocol (VPP) and Credential Issuance Protocol (CIP).

In addition, tests are grouped according to the system under test (SUT). For example, the Credential Service has to
complete the Verifiable Presentation Protocol tests as well as the Credential Issuance Protocol tests, while the Issuer
Service only has to complete the Credential Issuance Protocol tests.

The following matrix shows the SUTs and the tests they have to complete:

| SuT                | Verifiable Presentation Protocol | Credential Issuance Protocol |
|--------------------|----------------------------------|------------------------------|
| Credential Service | Yes                              | Yes                          |
| Issuer Service     | No                               | Yes                          |
| Verifier           | Yes                              | No                           |

### 1.1 Test packages

Test are grouped into packages according to the system under test (SUT) and the protocol they are testing:

- `org.eclipse.dataspacetck.dcp.verification.presentation` for the Verifiable Presentation Protocol tests targeting the
  Credential
  Service
- `org.eclipse.dataspacetck.dcp.verification.issuance.cs` for the Credential Issuance Protocol tests targeting the
  Credential Service
- `org.eclipse.dataspacetck.dcp.verification.issuance.issuer` for the Credential Issuance Protocol tests targeting the
  Issuer Service

## 2. Preconditions

### 2.1 Running instance of the system-under-test

The system under test (SUT) must be running and reachable via the network. If a SUT consists of several
microservices, it is allowed to only launch the microservices that are required for the tests. For example, if you want
to test the VPP, then only the microservice that processes Presentation Queries is required.

Further, the SecureTokenService must be running and reachable via the network. The TCK will use the SecureTokenService
to obtain ID Tokens for Presentation Query messages. The SUT must be prepared in such a way that there is a valid
`clientId/clientSecret` with which ID tokens can be obtained. This will be used as configuration for the TCK.

### 2.2 Required test data

The TCK dynamically generates two test credentials for every test case and attempts to load them into the SUT by sending
a
`CredentialMessage`
to the SUT's [Storage API](https://eclipse-dataspace-dcp.github.io/decentralized-claims-protocol/v1.0-RC3/#storage-api).
This means, the SuT must accept the test credentials on that API endpoint, otherwise all tests will fail.

### 2.3 Required configuration

The following configuration is required to run the TCK:

| Property                                  | Description                                                                                                                                                                                                                                                     | Example                          | Required by TCK |
|-------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|-----------------|
| `dataspacetck.callback.address`           | this is the loopback address of the TCK,<br/>for example to resolve test DID documents                                                                                                                                                                          | `http://localhost:8080`          | yes             |
| `dataspacetck.did.holder`                 | the DID of the holder (i.e. the CredentialService).<br>The holder's DID document must be [resolvable](https://w3c-ccg.github.io/did-method-web/#read-resolve) at this URL                                                                                       | `did:web:localhost%3A4711:holder | for VPP tests   |
| `dataspacetck.sts.url`                    | the URL of the SecureTokenService of the holder **not**<br>including the `/token` path element.<br>This is used to create ID Tokens for Presentation Query messages                                                                                             | `http://loclahost:8923/api/sts`  | for VPP tests   |
| `dataspacetck.sts.client.id`              | the client ID for making token requests against the SecureTokenService.                                                                                                                                                                                         | `some-client-id`                 | for VPP tests   |
| `dataspacetck.sts.client.secret`          | the client secret for making token requests against the SecureTokenService                                                                                                                                                                                      | `5up3r$3cr3t`                    | for VPP tests   |
| `dataspacetck.credentials.correlation.id` | the correlation ID for the issuance of the test credentials.<br>Some implementations may reject rogue (uncorrelated) `CredentialMessages`,<br>so this correlation ID provides a way to establish correlation. If omitted, a random UUID is generated by the TCK | `some-correlation-id`            | no              |

## 2. How to run it

### 3.1 Using the Docker image and Testcontainers

The recommended way is to run the TCK using
the [official Docker image](https://hub.docker.com/r/eclipsedataspacetck/dsp-tck-runtime). Although not required,
using [Testcontainers](https://www.testcontainers.org/) is a very convenient way to run
the TCK container. When the container is started, it will automatically execute the TCK tests against the system under
test using HTTP.

However, there are a few crucial things to note particularly regarding Docker networking. By default, the host system
gains access to services inside the container by exposing ports. In the case of the TCK, the port mapping must be fixed,
otherwise DID resolution may fail.

In addition to host->container communication, the TCK runtime must have network access to the host system, to send
messages to the system under test. To achieve this, three things are required:

- configuring an additional host: `host.docker.internal=host-gateway`
- using `host.docker.internal` for all URLs on the host system
- using `0.0.0.0` instead of `localhost` for URLs inside the container

```java

@DisplayName("Testing the Verifiable Presentation Protocol using TCK and Testcontainers")
@Test
void runVppTestsWithDocker() {
    var config = Map.of(
            "dataspacetck.callback.address", "http://0.0.0.0:8080",
            "dataspacetck.launcher", "org.eclipse.dataspacetck.dcp.system.DcpSystemLauncher",
            "dataspacetck.did.holder", "did:web:host.docker.internal%3A4711:holder",
            "dataspacetck.sts.url", "http://host.docker.internal:8923/api/sts",
            "dataspacetck.sts.client.id", "some-client-id", // must be accepted by the STS
            "dataspacetck.sts.client.secret", "5up3r$3cr3t", // must be accepted by the STS
            "dataspacetck.credentials.correlation.id", "my-correlation-id", // optional
            "dataspacetck.test.package", "org.eclipse.dataspacetck.dcp.verification.presentation"
    );

    try (var tckContainer = new GenericContainer<>("eclipsedataspacetck/dcp-tck-runtime:latest")
            .withExtraHost("host.docker.internal", "host-gateway")
            .withExposedPorts(8080)
            .withEnv(config)
    ) {
        tckContainer.setPortBindings(List.of("%s:%s".formatted(CALLBACK_PORT, CALLBACK_PORT)));
        tckContainer.start();
        var latch = new CountDownLatch(1);
        var hasFailed = new AtomicBoolean(false);
        tckContainer.followOutput(outputFrame -> {
            monitor.info(outputFrame.getUtf8String());
            if (outputFrame.getUtf8String().toLowerCase().contains("there were failing tests")) {
                hasFailed.set(true);
            }
            if (outputFrame.getUtf8String().toLowerCase().contains("test run complete")) {
                latch.countDown();
            }

        });

        assertThat(latch.await(1, TimeUnit.MINUTES)).isTrue();
        assertThat(hasFailed.get()).describedAs("There were failing TCK tests, please check the log output above").isFalse();
    }
}
```

### 3.2 Directly from a JUnit test

All DCP implementations that can make use of the JUnit 5 platform can launch the TCK directly from a JUnit test case. It
is important to note that even though both the SuT and the TCK run in the same process, all communication still happens
over HTTP.
The TCK can simply be run programmatically from a JUnit test:

```java

@BeforeEach
void setup() {
    startSystemUnderTest();
    configureSystemUnderTest();
}

@DisplayName("Testing the Verifiable Presentation Protocol using TCK")
@Test
void runVppTests() {

    var result = TckRuntime.Builder.newInstance()
            .properties(Map.of(
                    "dataspacetck.callback.address", "http://localhost:8080",
                    "dataspacetck.launcher", "org.eclipse.dataspacetck.dcp.system.DcpSystemLauncher",
                    "dataspacetck.did.holder", "did:web:localhost%3A4711:holder", // must be resolvable
                    "dataspacetck.sts.url", "http://localhost:8923/api/sts",
                    "dataspacetck.sts.client.id", "some-client-id", // must be accepted by the STS
                    "dataspacetck.sts.client.secret", "5up3r$3cr3t", // must be accepted by the STS
                    "dataspacetck.credentials.correlation.id", "my-correlation-id" // optional
            ))
            .addPackage("org.eclipse.dataspacetck.dcp.verification.presentation")
            .monitor(new ConsoleMonitor(true, true))
            .build()
            .execute();


    if (!result.getFailures().isEmpty()) {
        var failures = result.getFailures().stream()
                .map(f -> "- " + f.getTestIdentifier().getDisplayName() + " (" + f.getException() + ")")
                .collect(Collectors.joining("\n"));
        Assertions.fail(result.getTotalFailureCount() + " TCK test cases failed:\n" + failures);
    }
}
```

The following Maven dependencies are required:

- `org.eclipse.dataspacetck.dcp:dcp-testcases:<VERSION>`: for the test cases
- `org.eclipse.dataspacetck.dsp:tck-runtime:<VERSION>`: to launch the TCK from JUnit
- `org.eclipse.dataspacetck.dsp:core:<VERSION>`: for the ConsoleMonitor
- `org.eclipse.dataspacetck.dcp:dcp-system:<VERSION>`: for the launcher that runs the TCK test cases
- `org.junit.platform:junit-platform-launcher:<JUNIT_VERSION>`

### 3.3 Using the command line

If neither of the above options is suitable, the TCK can also be run from the command line, either using the Docker
image or building from source and executing the JAR file manually.

#### 3.3.1 Using the Docker image

```shell
docker pull eclipsedataspacetck/dcp-tck-runtime:latest

# not shown here: start and configure your system-under-test

docker run --rm \
   --add-host "host.docker.internal:host-gateway" \
   -p "8080:8080" \
   -e "DATASPACETCK_DID_HOLDER=did:web:host.docker.internal%3A4711:holder" \
   -e "DATASPACETCK_CALLBACK_ADDRESS=http://0.0.0.0:8080" \
   -e "DATASPACETCK_LAUNCHER=org.eclipse.dataspacetck.dcp.system.DcpSystemLauncher" \
   -e "DATASPACETCK_STS_URL=http://host.docker.internal:8923/api/sts" \
   -e "DATASPACETCK_CLIENT_ID=some-client-id" \
   -e "DATASPACETCK_CLIENT_SECRET=5up3r$3cr3t" \
   -e "DATASPACETCK_CREDENTIALS_CORRELATION_ID=my-correlation-id" \
   dcp-tck:latest
```

this will start the TCK and run all tests and print the test results to the console.

#### 3.3.2 Building from source

When building from source you will need git, Java 17 or higher and Gradle 8.0 or higher available on your system.

```shell
git clone https://github.com/eclipse-dataspacetck/dcp-tck.git
./gardlew shadowJar

# not shown here: start and configure your system-under-test

java -Ddataspacetck.callback.address="http://localhost:8080" \
  -Ddataspacetck.did.holder="did:web:localhost%3A4711:holder" \
  -Ddataspacetck.launcher="org.eclipse.dataspacetck.dcp.system.DcpSystemLauncher" \
  -Ddataspacetck.sts.url="http://localhost:8923/api/sts" \
  -Ddataspacetck.sts.client.id="some-client-id" \
  -Ddataspacetck.sts.client.secret="5up3r$3cr3t" \
  -Ddataspacetck.credentials.correlation.id="my-correlation-id" \
  -jar dcp-tck/build/libs/dcp-tck-runtime.jar
```