#!/bin/sh

cargo run --release -- --provider provider.comsk --public-coms-key customer.comsk.pub --dh-params dhparams.txt --sign-key provider.signk --meter-sign-pk meter.signk.pub 

