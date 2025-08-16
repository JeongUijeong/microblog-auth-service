FROM eclipse-temurin:21-jdk-alpine

VOLUME /tmp
ARG JAR_FILE=build/libs/*.jar
COPY ${JAR_FILE} app.jar

# wait-for-it.sh
COPY wait-for-it.sh ./
RUN chmod +x wait-for-it.sh

EXPOSE 8081

ENTRYPOINT ["java", "-jar", "/app.jar"]