# Java interop client (java.net.http, HTTP/2). Run via single-file source launch
# (java Interop.java), so no build tool. Brotli decode needs a library, so fetch
# the org.brotli:dec jar from Maven Central and put it on the classpath.
FROM eclipse-temurin:21-alpine
WORKDIR /app
ARG BROTLI_DEC=https://repo1.maven.org/maven2/org/brotli/dec/0.1.2/dec-0.1.2.jar
RUN wget -q -O /libs-dec.jar "$BROTLI_DEC"
COPY Interop.java .
CMD ["java", "-cp", "/libs-dec.jar", "Interop.java"]
