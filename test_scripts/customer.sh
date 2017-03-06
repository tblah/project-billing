#!/bin/sh

cargo run -- --customer customer.comsk --public-coms-key provider.comsk.pub --dh-params dhparams.txt --sign-trusted-pk meter.signk.pub

