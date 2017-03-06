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
use proj_billing::billing::three_party::*;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::exit;
use proj_billing::billing::Keys;
use proj_billing::billing::consumption::integer_consumption::IntegerConsumption;

const DEFAULT_WAN_SOCKET_ADDR: &'static str = "127.0.0.1:1025";
const DEFAULT_LAN_SOCKET_ADDR: &'static str = "127.0.0.1:1026";

fn print_usage(executable_name: &str, opts: &Options) -> ! {
    println!("\n{} is free software licenced under GPLv3+: you are free to change and redistribute it.", executable_name);
    println!("There is NO WAARRANTY, to the extent permitted by law.");
    println!("The cryptography used has not been reviewed by any experts. You should not use it for anything serious.\n");
    
    let brief1 = format!("To generate communication (and optionally: signing) keys: {} --keygen OUTPUT_FILE [--sign-key OUTPUT_FILE2]\n", executable_name);
    let brief2 = format!("To run a provider: {} --provider MY_KEYPAIR --public-coms-key PUBLIC_KEY_FILE --dh-params DH_PARAMS --sign-key SIGN_KEY --sign-trusted-pk SIGN_PUBKEY --meter-sign-pk SIGN_PUBKEY [--wan-socket IPADDR:PORT]\n", executable_name);
    let brief3 = format!("To run a customer: {} --customer MY_KEYPAIR --public-coms-key PUBLIC_KEY_FILE --dh-params DH_PARAMS --meter-sign-pk SIGN_PUBKEY --provider-sign-pk SIGN_PUBKEY [--wan-socket IPADDR:PORT] [--lan-socket IPADDR:PORT]\n", executable_name);
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
    opts.optopt("d", "dh-params", "The diffie-hellman parameters for the commitments", "DH_PARAMS");

    // required for meter and provider
    opts.optopt("k", "sign-key", "The secret key for signing billing messages", "SIGN_KEY");

    // required for the customer
    opts.optopt("p", "provider-sign-pk", "The public key for verifying signatures", "SIGN_PUBKEY");

    // required for customer and provider
    opts.optopt("m", "meter-sign-pk", "The public key used to verify signatures from the meter", "SIGN_PUBKEY");

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
    sodiumoxide::init();
    
    if matches.opt_present("keygen") {
        // incompatible options
        if matches.opt_present("public-coms-key") | matches.opt_present("dh-params") | matches.opt_present("meter-sign-pk") | matches.opt_present("provider-sign-pk") | matches.opt_present("lan-socket") | matches.opt_present("wan-socket") {
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
        if matches.opt_present("lan-socket") | matches.opt_present("provider-sign-pk") {
            println!("That is not a compatible option for provider");
            print_usage(&executable_name, &opts);
        }

        // required options
        if !(matches.opt_present("public-coms-key") && matches.opt_present("dh-params") && matches.opt_present("sign-key") && matches.opt_present("meter-sign-pk")) {
            println!("Missing some required option");
            print_usage(&executable_name, &opts);
        }

        // optional 
        let wan_socket = if matches.opt_present("wan-socket") {
            matches.opt_str("wan-socket").unwrap()
        } else {
            String::from(DEFAULT_WAN_SOCKET_ADDR)
        };

        start_provider(matches.opt_str("dh-params").unwrap(), matches.opt_str("provider").unwrap(),
                       matches.opt_str("public-coms-key").unwrap(), matches.opt_str("sign-key").unwrap(),
                       matches.opt_str("meter-sign-pk").unwrap(), wan_socket);
    }

    if matches.opt_present("customer") {
        // incompatible options
        if matches.opt_present("sign-key") {
            println!("sign-key is not a compatible option for customer");
            print_usage(&executable_name, &opts);
        }

        // required options
        if !(matches.opt_present("public-coms-key") && matches.opt_present("dh-params") && matches.opt_present("meter-sign-pk") && matches.opt_present("provider-sign-pk")) {
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
        
        start_customer(matches.opt_str("dh-params").unwrap(), matches.opt_str("customer").unwrap(),
                       matches.opt_str("public-coms-key").unwrap(), matches.opt_str("meter-sign-pk").unwrap(),
                       matches.opt_str("provider-sign-pk").unwrap(), wan_socket, lan_socket);
    }

    if matches.opt_present("meter") {
        // incompatible options
        if matches.opt_present("public-coms-key") | matches.opt_present("meter-sign-pk") | matches.opt_present("provider-sign-pk") | matches.opt_present("wan-socket") {
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

        start_meter(matches.opt_str("dh-params").unwrap(), matches.opt_str("sign-key").unwrap(), lan_socket);
    }

    println!("No mode specified!");
    print_usage(&executable_name, &opts);
}

fn assert_file_exists(path_str: &String) {
    let path = Path::new(path_str);

    if !(path.is_file()) {
        println!("{} is not a file. Exiting.", path_str);
        exit(1); // failure
    }
}

fn start_meter(dhparams_path: String, sign_key_path: String, lan_socket_path: String) -> ! {
    assert_file_exists(&sign_key_path);

    println!("Starting a meter on {} using the diffie-hellman parameters at {} and the signing key at {}", lan_socket_path, dhparams_path, sign_key_path);
    
    // get dh-params
    let dh_params = read_or_gen_params(dhparams_path);

    // get signing key
    let (_, sk) = sign::get_keypair(sign_key_path);

    // set up channel
    let channel = match TcpStream::connect(lan_socket_path.as_str()) {
        Ok(c) => c,
        Err(e) => {
            println!("Error connecting to {}: {}.", lan_socket_path, e);
            exit(1);
        },
    };

    let meter = MeterState::new(channel, sk, dh_params);

    let mut shell = shell::InteractiveShell::new("meter", meter);

    // consume command
    fn consume(meter: &mut MeterState<TcpStream>, args: Vec<String>) {
        if args.len() != 2 {
            println!("There should be two integer arguments to this command: cons and other");
            return;
        }

        let cons: i32 = match args[0].parse() {
            Ok(c) => c,
            Err(_) => {
                println!("Error parsing cons. It should be a 32 bit signed integer.");
                return;
            },
        };

        let other: u8 = match args[1].parse() {
            Ok(o) => o,
            Err(_) => {
                println!("Error parsing other. It should be a unsigned integer lower than 168");
                return;
            },
        };

        if other >= 168 {
            println!("Other should be lower than 168 (it is an hour in a week)");
            return;
        }

        meter.consume(&IntegerConsumption{ hour_of_week: other, units_consumed: cons });
    }

    shell.register_command("consume", "consume CONS OTHER\t", "Consumer CONS units at time OTHER", Box::new(consume));
    
    shell.start();
}

fn start_customer(dhparams_path: String, private_coms_key_path: String, public_coms_key_path: String, meter_sign_pk_path: String,
                  provider_sign_pk_path: String, wan_socket: String, lan_socket: String) -> !{
    assert_file_exists(&private_coms_key_path);
    assert_file_exists(&public_coms_key_path);
    assert_file_exists(&meter_sign_pk_path);
    assert_file_exists(&provider_sign_pk_path);

    println!("Starting a customer on on {} (LAN) -> {} (WAN) using communication keys {} and {} and trusting signing keys {} and {}", lan_socket, wan_socket, private_coms_key_path, public_coms_key_path, meter_sign_pk_path, provider_sign_pk_path);

    // get dh-params
    let dh_params = read_or_gen_params(dhparams_path);

    // get coms keys
    let (coms_pks, coms_keys) = get_keys(private_coms_key_path, public_coms_key_path);

    // get signing public keys
    let meter_sign_pk = sign::get_pubkey(meter_sign_pk_path);
    let provider_sign_pk = sign::get_pubkey(provider_sign_pk_path);

    // start listening for connections from the meter
    let listener = match TcpListener::bind(lan_socket.as_str()) {
        Err(e) => { panic!("Error listening for TCP connections: {}.", e); }
        Ok(l) => {l},
    };

    // start crypto with provider
    let mut client = match client::start(wan_socket.as_str(), coms_keys, &coms_pks) {
        Err(e) => panic!("Client failed to start with error {:?}", e),
        Ok(c) => c,
    };
    client.blocking_off(1);

    let meter_stream = listener.incoming().next().unwrap().unwrap();
    meter_stream.set_nonblocking(true).expect("set_nonblocking call in start_customer failed");
    
    let customer = CustomerState::new(meter_stream, client, [1; 24*7], provider_sign_pk, meter_sign_pk, dh_params);

    let mut shell = shell::InteractiveShell::new("customer", customer);

    // shell commands
    fn get_consumption(customer: &mut CustomerState<client::Client, TcpStream>, args: Vec<String>) {
        shell::complain_arg(&args);
        customer.read_meter_messages();
    }

    shell.register_command("get_cons", "get_cons\t\t", "Receive consumption messages from the smartmeter", Box::new(get_consumption));

    fn get_prices(customer: &mut CustomerState<client::Client, TcpStream>, args: Vec<String>) {
        shell::complain_arg(&args);
        customer.read_provider_messages();
    }

    shell.register_command("get_prices", "get_prices\t\t", "Receive new prices from the provider", Box::new(get_prices));

    fn send_bill(customer: &mut CustomerState<client::Client, TcpStream>, args: Vec<String>) {
        shell::complain_arg(&args);
        println!("Checking for new prices...");
        customer.read_provider_messages();
        println!("Checking for new consumption statistics...");
        customer.read_meter_messages();
        println!("Calculating the bill and the proof...");
        println!("The bill is {}.", customer.send_billing_information());
    }

    shell.register_command("send_bill", "send_bill\t\t", "Send the bill and proof to the provider", Box::new(send_bill));
    
    fn cons_table(customer: &mut CustomerState<client::Client, TcpStream>, args: Vec<String>) {
        shell::complain_arg(&args);
        customer.read_meter_messages();
        println!("{}", customer.readable_consumption_table());
    }

    shell.register_command("cons_table", "cons_table\t\t", "Display the state of the consumption table", Box::new(cons_table));

    shell.start();
}

fn start_provider(dhparams_path: String, private_coms_key_path: String, public_coms_key_path: String, sign_key_path: String, sign_trusted_pk_path: String, wan_socket: String) -> ! {
    assert_file_exists(&private_coms_key_path);
    assert_file_exists(&public_coms_key_path);
    assert_file_exists(&sign_key_path);
    assert_file_exists(&sign_trusted_pk_path);

    println!("Starting a provider on {}, using the diffie-hellman parameters at {}, communication keys at {} and {} and signing keys at {} and {}", wan_socket, dhparams_path, private_coms_key_path, public_coms_key_path, sign_key_path, sign_trusted_pk_path);

    // get dh-params
    let dh_params = read_or_gen_params(dhparams_path);

    // get coms keys
    let (coms_pks, coms_keys) = get_keys(private_coms_key_path, public_coms_key_path);

    // get signing keys
    let (_, sign_sk) = sign::get_keypair(sign_key_path);
    let sign_pk = sign::get_pubkey(sign_trusted_pk_path);

    // start listening for connections
    let listener = match TcpListener::bind(wan_socket.as_str()) {
        Err(e) => { panic!("Error listening for TCP connections: {}.", e); }
        Ok(l) => {l},
    };

    // begin crypto on first connection
    let server = server::do_key_exchange(listener.incoming().next().unwrap(), &coms_keys, &coms_pks).unwrap();

    // begin billing protocol layer
    let provider = ProviderState::new(server, [1; 7*24], Keys{ my_sk: sign_sk, their_pk: sign_pk }, dh_params);

    let mut shell = shell::InteractiveShell::new("provider", provider);

    // shell commands
    fn get_bill(provider: &mut ProviderState<server::Server>, args: Vec<String>) {
        shell::complain_arg(&args);
        provider.receive_billing_information();

        println!("The bill is {}", provider.pay_bill());
    }

    shell.register_command("get_bill", "get_bill\t\t", "Receive billing information from the customer and check that was calculated honestly", Box::new(get_bill));

    fn change_price(provider: &mut ProviderState<server::Server>, args: Vec<String>) {
        if args.len() != 2 {
            println!("There should be two integer arguments to this command: new_price and the corresponding hour of the week");
            return;
        }

        let new_price: i32 = match args[0].parse() {
            Ok(p) => p,
            Err(_) => {
                println!("Error parsing the new price. It should be a 32-bit signed integer.");
                return;
            },
        };

        let other: u8 = match args[1].parse() {
            Ok(o) => o,
            Err(_) => {
                println!("Error parsing other. It should be a unsigned integer lower than 168");
                return;
            },
        };

        if other >= 168 {
            println!("Other should be lower than 168 (it is an hour in a week)");
            return;
        }

        let mut new_prices = provider.prices;
        new_prices[other as usize] = new_price;
        
        provider.change_prices(&new_prices);
    }

    shell.register_command("change_price", "change_price NEW_PRICE HOUR", "Change the price for a specified hour and send the new prices to the customer", Box::new(change_price));

    shell.start();
}
