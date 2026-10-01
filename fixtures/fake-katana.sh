#!/bin/sh
set -eu

for arg in "$@"; do
    if [ "$arg" = "-version" ]; then
        echo "katana version 1.3.0"
        exit 0
    fi
done

printf '%s\n' \
'{"request":{"method":"GET","endpoint":"https://app.example.test/"},"response":{"status_code":200}}' \
'{"request":{"method":"GET","endpoint":"https://app.example.test/login"},"response":{"status_code":200}}' \
'{"request":{"method":"GET","endpoint":"https://app.example.test/api/users?x=1"},"response":{"status_code":200}}' \
'{"request":{"method":"GET","endpoint":"https://outside.test/"}}' \
'{"request":{"method":"GET","endpoint":"https://app.example.test/login"}}'
