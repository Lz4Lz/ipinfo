#!/bin/bash

gcc ipinfo.c -o ipinfo -Wall -pedantic -ljson-c

sleep 1

./ipinfo -h

echo "ok done enjoy"
