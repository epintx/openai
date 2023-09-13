#!/bin/bash
git fetch
git pull --rebase
docker stop openai
docker rm openai
docker run -d -p 80:80 -v $PWD/openaiBin:/app/openaiBin -v $PWD/template.html:/app/template.html -v $PWD/log:/app/log -v $PWD/config.yaml:/app/config.yaml --name openai tomatocuke/openai
