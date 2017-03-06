#!/bin/sh

cargo run --release -- --customer customer.comsk --public-coms-key provider.comsk.pub --dh-params dhparams.txt --meter-sign-pk meter.signk.pub --provider-sign-pk provider.signk.pub

