# Notice for Docker image

A DCP TCK runtime that performs compatibility tests against a running credential service, issuer service and verifier
instance.

DockerHub: <https://hub.docker.com/r/eclipsedataspacetck/dcp-tck-runtime>

Eclipse Dataspace TCK product(s) installed within the image:

## DCP TCK Runtime

- GitHub: <https://github.com/eclipse-dataspacetck/dcp-tck>
- Project home: <https://projects.eclipse.org/projects/technology.dataspacetck>
- Dockerfile: <https://github.com/eclipse-dataspacetck/dcp-tck/blob/main/dcp-tck/src/main/docker/Dockerfile>
- Project license: [Apache License, Version 2.0](https://github.com/eclipse-tractusx/tractusx-edc/blob/main/LICENSE)

## Used base image

- [eclipse-temurin:23.0.1_11-jre-alpine](https://github.com/adoptium/containers)
- Official Eclipse Temurin DockerHub page: <https://hub.docker.com/_/eclipse-temurin>
- Eclipse Temurin Project: <https://projects.eclipse.org/projects/adoptium.temurin>
- Additional information about the Eclipse Temurin
  images: <https://github.com/docker-library/repo-info/tree/master/repos/eclipse-temurin>

## Third-Party Software

As with all Docker images, these likely also contain other software which may be under other licenses (such as Bash, etc
from the base distribution, along with any direct or indirect dependencies of the primary software being contained).

As for any pre-built image usage, it is the image user's responsibility to ensure that any use of this image complies
with any relevant licenses for all software contained within.
