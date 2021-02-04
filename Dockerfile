FROM openjdk:11-jre-stretch
MAINTAINER Eugene Azarenko

WORKDIR /var/oidc-server

ADD oidc-server.jar /var/oidc-server/auth-server.jar
ADD config.yml /var/oidc-server/config.yml
ADD id-token-key /var/oidc-server/secrets/id-token-key
ADD access-token-key /var/oidc-server/secrets/access-token-key
ADD admin-token /var/oidc-server/secrets/admin-token

EXPOSE 9000 9001

ENTRYPOINT ["java", "-jar", "oidc-server.jar", "server", "config.yml"]
