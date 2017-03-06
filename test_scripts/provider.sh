#!/bin/sh

cargo run -- --provider provider.comsk --public-coms-key customer.comsk.pub --dh-params dhparams.txt --sign-key provider.signk --sign-trusted-pk meter.signk.pub 

