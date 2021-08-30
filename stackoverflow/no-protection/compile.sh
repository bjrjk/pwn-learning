#!/bin/sh
gcc hello.c -g -o hello -zexecstack -fno-stack-protector -no-pie
