#!/bin/sh
# log_writer.sh - append a heartbeat line to a local log
mkdir -p /guest/www
echo "$(date) - heartbeat" >> /guest/www/heartbeat.log
