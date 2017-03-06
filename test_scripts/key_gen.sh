#!/bin/sh

set -e 

EXEC="cargo run --release -- --keygen"

$EXEC customer.comsk --sign-key meter.signk

$EXEC provider.comsk --sign-key provider.signk

