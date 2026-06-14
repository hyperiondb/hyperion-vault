#!/bin/sh
set -eu

wg-quick up wg0

trap 'wg-quick down wg0 || true; exit 0' TERM INT

while :; do
    sleep 3600 &
    wait "$!" || true
done
