#!/bin/bash
# kill daemon
sudo kill 9 `ps -aux | grep rate_limiter | awk '{print $2}'`

make clean
make

# run service with root privilege
sudo ./rate_limiter
