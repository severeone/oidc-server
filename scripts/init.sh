#!/bin/bash
MODE=${1:-local}
echo "$MODE" > clean-test-db-mode
mustache $MODE.yml ../src/test/resources/config_for_test.template > ../src/test/resources/config_for_test.yml
mustache $MODE.yml ../config.template > ../config.yml
cd ../ 
./db/db.py --debug --password=oidcpwd $MODE change start
./db/db.py --debug --password=oidcpwd $MODE test reinstall
