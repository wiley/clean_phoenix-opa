#!/bin/sh

./opa test --format=json ./policies > report.json
./opa_test_to_junit.py report.json > ./reports/junit.xml