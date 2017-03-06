//! Executable for demonstrating the three party billing protocol

/*  This file is part of project-net.
    project-net is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    project-net is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with project-net.  If not, see http://www.gnu.org/licenses/.*/

mod shell;

extern crate getopts;
extern crate proj_crypto;
extern crate proj_net;
extern crate proj_billing;
extern crate sodiumoxide;

use getopts::Options;
use std::env;
use std::process;
use proj_net::*;
use proj_crypto::asymmetric::sign;

const DEFAULT_WAN_SOCKET_ADDR: &'static str = "127.0.0.1:1025";
const DEFAULT_LAN_SOCKET_ADDR: &'static str = "127.0.0.1:1026";

fn print_usage(executable_name: &str, opts: &Options) -> ! {
    println!("\n{} is free software licenced under GPLv3+: you are free to change and redistribute it.", executable_name);
    println!("There is NO WAARRANTY, to the extent permitted by law.");
    println!("The cryptography used has not been reviewed by any experts. You should not use it for anything serious.\n");
    
    let brief1 = format!("To generate communication (and optionally: signing) keys: {} --keygen OUTPUT_FILE [--sign-key OUTPUT_FILE2]\n", executable_name);
    let brief2 = format!("To run a provider: {} --provider MY_KEYPAIR --public-coms-key PUBLIC_KEY_FILE --dh-params DH_PARAMS --sign-key SIGN_KEY --sign-trusted-pk SIGN_PUBKEY [--wan-socket IPADDR:PORT]\n", executable_name);
    let brief3 = format!("To run a customer: {} --customer MY_KEYPAIR --public-coms-key PUBLIC_KEY_FILE --dh-params DH_PARAMS --sign-trusted-pk SIGN_PUBKEY [--wan-socket IPADDR:PORT] [--lan-socket IPADDR:PORT]\n", executable_name);
    let brief4 = format!("To run a meter: {} --meter --dh-params DH_PARAMS --sign-key SIGN_KEY [--lan-socket IPADDR:PORT]\n", executable_name);
    
    print!("{}", opts.usage(&(brief1+&brief2+&brief3+&brief4)));
    process::exit(1)
}

// handles command line arguments
fn main() {
    let args: Vec<String> = env::args().collect();
    let executable_name = args[0].clone();

    let mut opts = Options::new();

    // prints usage - optional, no argument
    opts.optflag("h", "help", "Print this help menu");

    // key generation mode - optional, takes an argument
    opts.optopt("", "keygen", "Generate a long term keypair for communication into OUTPUTFILE (both keys) and OUTFILE.pub (just the public key)", "OPUTPUT_FILE");

    // provider mode - optional, takes an argument
    opts.optopt("", "provider", "Starts a provider", "MY_COMS_KEYPAIR");

    // customer mode - optional, takes an argument
    opts.optopt("", "customer", "Starts a customer", "MY_COMS_KEYPAIR");

    // meter mode - optional, takes an argument
    opts.optflag("", "meter", "Starts a meter");

    // required for provider and customer
    opts.optopt("c", "public-coms-key", "The trusted public keys for communication", "PUBLIC_KEY_FILE");

    // required for all main modes
    opts.optopt("p", "dh-params", "The diffie-hellman parameters for the commitments", "DH_PARAMS");

    // required for meter and provider
    opts.optopt("k", "sign-key", "The secret key for signing billing messages", "SIGN_KEY");

    // required for provider and customer
    opts.optopt("s", "sign-trusted-pk", "The public key for verifying signatures", "SIGN_PUBKEY");

    // required for meter and customer
    opts.optopt("l", "lan-socket", &format!("The socket for communication between the customer and meter. The default is {}.", DEFAULT_LAN_SOCKET_ADDR), "IPADDR:PORT");

    // required for customer and provider
    opts.optopt("w", "wan-socket", &format!("The socket for communication between the customer and provider. The default is {}.", DEFAULT_WAN_SOCKET_ADDR), "IPADDR:PORT");

    // parse options
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => { println!("{}", f.to_string()); print_usage(&executable_name, &opts)},
    };

    if matches.opt_present("help") {
        print_usage(&executable_name, &opts);
    }

    // enforce exclusivity between operation modes
    if (matches.opt_present("keygen") && (matches.opt_present("provider") | matches.opt_present("customer") | matches.opt_present("meter"))) |
        (matches.opt_present("provider") && (matches.opt_present("customer") | matches.opt_present("meter"))) |
        (matches.opt_present("customer") && matches.opt_present("meter")) {

        println!("Use only one mode at a time.\n");
        print_usage(&executable_name, &opts);
    }

    // actually do stuff
    if matches.opt_present("keygen") {
        // incompatible options
        if matches.opt_present("public-coms-key") | matches.opt_present("dh-params") | matches.opt_present("sign-trusted-pk") | matches.opt_present("lan-socket") | matches.opt_present("wan-socket") {
            println!("Those options do not work with keygen");
            print_usage(&executable_name, &opts);
        }

        if matches.opt_present("sign-key") {
            sign::key_gen_to_file(matches.opt_str("sign-key").unwrap().as_str());
        }

        return key_gen_to_file(matches.opt_str("keygen").unwrap().as_str());
    }
    
    if matches.opt_present("provider") {
        // incompatible options
        if matches.opt_present("lan-socket") {
            println!("lan-socket is not a compatible option for provider");
            print_usage(&executable_name, &opts);
        }

        // required options
        if !(matches.opt_present("public-coms-key") && matches.opt_present("dh-params") && matches.opt_present("sign-key") && matches.opt_present("sign_trusted_pk")) {
            println!("Missing some required option");
            print_usage(&executable_name, &opts);
        }

        // optional 
        let wan_socket = if matches.opt_present("wan-socket") {
            matches.opt_str("wan-socket").unwrap()
        } else {
            String::from(DEFAULT_WAN_SOCKET_ADDR)
        };

        println!("I am a happy provider on {}", wan_socket);
        return;
    }

    if matches.opt_present("customer") {
        // incompatible options
        if matches.opt_present("sign-key") {
            println!("sign-key is not a compatible option for customer");
            print_usage(&executable_name, &opts);
        }

        // required options
        if !(matches.opt_present("public-coms-key") && matches.opt_present("dh-params") && matches.opt_present("sign-trusted-pk")) {
            println!("Missing some required option");
            print_usage(&executable_name, &opts);
        }

        // optional
        let wan_socket = if matches.opt_present("wan-socket") {
            matches.opt_str("wan-socket").unwrap()
        } else {
            String::from(DEFAULT_WAN_SOCKET_ADDR)
        };

        let lan_socket = if matches.opt_present("lan-socket") {
            matches.opt_str("lan-socket").unwrap()
        } else {
            String::from(DEFAULT_LAN_SOCKET_ADDR)
        };
        
        println!("I am a happy customer on {} (WAN) and {} (LAN)", wan_socket, lan_socket);
        return;
    }

    if matches.opt_present("meter") {
        // incompatible options
        if matches.opt_present("public-coms-key") | matches.opt_present("sign-trusted-pk") | matches.opt_present("wan-socket") {
            println!("Those options do not work with meter");
            print_usage(&executable_name, &opts);
        }

        // required options
        if !(matches.opt_present("dh-params") && matches.opt_present("sign-key")) {
            println!("Missing some required option");
            print_usage(&executable_name, &opts);
        }

        let lan_socket = if matches.opt_present("lan-socket") {
            matches.opt_str("lan-socket").unwrap()
        } else {
            String::from(DEFAULT_LAN_SOCKET_ADDR)
        };

        let mut shell = shell::InteractiveShell::new("meter", ());
        shell.start();
        return;
    }

    println!("No mode specified!");
    print_usage(&executable_name, &opts);
}
