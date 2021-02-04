#!/bin/bash
MODE=`cat clean-test-db-mode`
cd ../ && ./db/db.py --debug --password=oidcpwd $MODE test reinstall
