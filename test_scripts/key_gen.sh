#!/bin/sh

set -e 

EXEC="cargo run -- --keygen"

$EXEC customer.comsk --sign-key meter.signk

$EXEC producer.comsk --sign-key producer.signk

