#!/bin/bash

IMAGE_TAG=$1

docker stop auth-server > /dev/null
docker rename auth-server auth-server-old > /dev/null

$(aws ecr get-login --no-include-email --region us-west-1)

docker tag severeone/oidc-server:${IMAGE_TAG} severeone/oidc-server:old > /dev/null
docker rmi severeone/oidc-server:${IMAGE_TAG} > /dev/null

docker run -d --restart always --name auth-server -p 9000:9000 -p 9001:9001 --label auth-server --net=host severeone/oidc-server:${IMAGE_TAG}

if [ $? -eq 0 ]; then
   docker rm auth-server-old
   docker rmi severeone/oidc-server:old > /dev/null
   echo "SUCCESS"
else
   docker tag severeone/oidc-server:old severeone/oidc-server:${IMAGE_TAG} > /dev/null
   docker rmi severeone/oidc-server:old > /dev/null
   docker rename auth-server-old auth-server
   docker start auth-server
   echo "FAILURE"
   exit 1
fi
