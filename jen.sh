#!/bin/bash
stty -echoctl
./jen $1 $2 $3
echo "Result Code:" $?