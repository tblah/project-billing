#!/bin/sh

set -e 

EXEC="cargo run --release -- --keygen"

$EXEC customer.comsk --sign-key meter.signk

$EXEC producer.comsk --sign-key producer.signk

