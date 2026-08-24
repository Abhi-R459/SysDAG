#!/bin/sh
# backdoor.sh - creates/truncates a file and executes a shell command (malicious pattern)
echo "touching backdoor" > /guest/www/backdoor.txt
chmod +x /guest/www/backdoor.txt
/bin/sh -c "echo pwned > /guest/www/backdoor.txt"
