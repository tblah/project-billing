//! # Three Party Billing Scheme
//!
//! 1. Utility provider
//! 2. Smart meter (trusted by all parties)
//! 3. Customer hardware (calculates the bill and performs the external communication to the provider)
//!
//! The meter signs and commits to readings. The consumer may then perform computations on them which can be blindly verified by the utility provider, without the provider having to know the individual readings.
//!
//! For the implementation of BillingProtocol (for tests), the Customer and Smart Meter are handled together.

/*  This file is part of project-billing.
    project-billing is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    project-billing is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with project-billing.  If not, see http://www.gnu.org/licenses/.*/

use super::consumption::integer_consumption::*;
use super::consumption::Consumption;
use super::common;
use std::io::{Read, Write};
use proj_crypto::asymmetric::{sign, commitments};
use gmp::mpz::Mpz;
use std::io;
use std::path::Path;

/// The default file to store diffie-hellman parameters in
pub static DEFAULT_PARAMS_PATH: &'static str = "dhparams.txt";

/// Try to read DHParams from the provided file. If this fails, then generate new parameters and write these to the file
pub fn read_or_gen_params<P: AsRef<Path> + Clone>(path: P) -> commitments::DHParams {
    match commitments::read_dhparams(path.clone()) {
        Ok(params) => params,
        Err(_) => {
            let params = commitments::gen_dh_params().unwrap();
            let _ = commitments::write_dhparams(&params, path);
            params
        }
    }
}

/// State associated with the smart meter
pub struct MeterState<T: Read + Write> {
    /// Channel through which to communicate with the customer
    channel: T,
    /// Signing key
    sk: sign::SecretKey,
    /// Commitment parameters
    params: commitments::DHParams,
}

fn stringify_bytes(bytes: &[u8]) -> String {
    let mut ret = String::new();

    for byte in bytes {
        ret += &format!("{} ", byte);
    }

    ret
}

fn unstringify_bytes(string: &str) -> Vec<u8> {
    let mut ret = Vec::new();

    for str in string.split_whitespace() {
        ret.push(u8::from_str_radix(str, 10).unwrap());
    }

    ret
}

fn read_up_to_newline<R: Read>(source: &mut io::Bytes<R>) -> Vec<u8> {
    let mut iterator = source.map(|x| x.unwrap());

    let ret: Vec<u8> = iterator.by_ref().take_while(|x| *x != b'\n').collect();
    //assert_eq!(b'\n', iterator.next().unwrap()); // get rid of the separating \n

    ret
}

// separate function so I can test it more easily
fn meter_consume<W: Write>(params: &commitments::DHParams, sk: &sign::SecretKey, channel: &mut W, consumption: &IntegerConsumption) {
    assert!(consumption.is_valid());

    let cons_int = consumption.units_consumed;

    let a = commitments::random_a(&params.1);
    let a_str = a.to_str_radix(16);

    let commit_context = commitments::CommitmentContext::from_opening((Mpz::from(cons_int), a), params.clone()).unwrap();
    let commitment = commit_context.to_commitment();
    let commitment_str = commitment.x.to_str_radix(16);

    // send (cons, a) + sign(commit, other)

    let touple_str = format!("{} {}", cons_int, a_str);
    let thing_to_sign = format!("{} {}", commitment_str, consumption.hour_of_week);
    let signed_commitment = sign::sign(&thing_to_sign.as_bytes(), &sk);

    let message_str = touple_str + "\n" + &stringify_bytes(&signed_commitment) + "\n";
    let message = message_str.as_bytes();

    // actually send it
    match channel.write(&message) {
        Ok(s) => assert_eq!(s, message.len()),
        Err(e) => panic!("Failed to send the consumption data. The error was {}", e),
    };
}

// separate function so that I can test it more easily
fn customer_read_consumption<R: Read>(channel: &mut R, meter_key: &sign::PublicKey, table: &mut Vec<ConsumptionTableRow>) {
    // read the two newline separated stringified signatures
    let mut iterator = channel.bytes();

    // read touple str
    let touple_str = String::from_utf8(read_up_to_newline(&mut iterator)).unwrap();

    // read the signed commitment
    let signed_commitment_str_bytes = read_up_to_newline(&mut iterator);
    let signed_commitment_other = unstringify_bytes(&String::from_utf8(signed_commitment_str_bytes.clone()).unwrap());

    // verify the signature on the commitment
    let commitment_other_bytes = sign::verify(&signed_commitment_other, meter_key).unwrap();
    let commit_other_str = String::from_utf8(commitment_other_bytes).unwrap();
    let mut commit_other_iter = commit_other_str.split_whitespace();
    let _ = commit_other_iter.next().unwrap();
    let other_str = commit_other_iter.next().unwrap();
    assert_eq!(None, commit_other_iter.next());

    // touple looks like "cons a"
    let mut touple_iter = touple_str.split_whitespace();
    let cons_str = touple_iter.next().unwrap();
    let a_str = touple_iter.next().unwrap();
    assert_eq!(None, touple_iter.next());

    let cons = i32::from_str_radix(&cons_str, 10).unwrap();
    let other = u8::from_str_radix(&other_str, 10).unwrap();
    let a = Mpz::from_str_radix(&a_str, 16).unwrap();

    let table_row = ConsumptionTableRow {
        signed_commitment: String::from_utf8(signed_commitment_str_bytes).unwrap(),
        cons: cons,
        other: other,
        a: a,
    };
        
    table.push(table_row);
}
    
impl<T: Read + Write> MeterState<T> {
    /// Create a new MeterState object
    pub fn new(channel: T, sk: sign::SecretKey, params: commitments::DHParams) -> MeterState<T> {
        //assert!(commitments::verify_dh_params(&params));
        MeterState {
            channel: channel,
            sk: sk,
            params: params
        }
    }

    /// Called once every hour with the consumption incurred in that hour
    pub fn consume(&mut self, consumption: &IntegerConsumption) {
        meter_consume(&self.params, &self.sk, &mut self.channel, consumption);
    }
}

struct ConsumptionTableRow {
    signed_commitment: String,
    cons: i32,
    other: u8,
    a: Mpz,
}

/// State associated with the customer
pub struct CustomerState<P: Read + Write, M: Read + Write> {
    /// Channel through which to communicate with the meter
    meter_channel: M,
    /// Channel through which to communicate with the provider
    provider_channel: P,
    /// The stored consumptions since the last bill was paid
    consumption_table: Vec<ConsumptionTableRow>,
    /// The prices currently used to calculate the bill
    pub prices: Prices,
    /// Public key of the provider for the verification of their prices
    provider_key: sign::PublicKey,
    /// Public key of the meter for verification of consumption data
    meter_key: sign::PublicKey,
    /// Commitment parameters
    params: commitments::DHParams,
}

impl<P: Read + Write, M: Read + Write> CustomerState<P, M> {
    /// Create a new CustomerState
    pub fn new(meter_channel: M, provider_channel: P, prices: Prices, provider_key: sign::PublicKey,
               meter_key: sign::PublicKey, params: commitments::DHParams)
               -> CustomerState<P, M> {
        //assert!(commitments::verify_dh_params(&params));
        CustomerState {
            meter_channel: meter_channel,
            provider_channel: provider_channel,
            consumption_table: Vec::new(),
            prices: prices,
            provider_key: provider_key,
            meter_key: meter_key,
            params: params,
        }
    }

    /// Calculate the bill and send it to the provider
    pub fn send_billing_information(&mut self) {
        // calculate what we think that the bill will be and what we expect a to be
        let mut bill = 0 as i64;
        let mut a = Mpz::zero();

        for row in &self.consumption_table {
            bill += row.cons as i64 * self.prices[row.other as usize] as i64;
            a = (a + row.a.clone() * self.prices[row.other as usize] as i64).modulus(&self.params.0);
        }

        // Message format: "bill\na\ntable.len()\ntable[0]\n...\n\table[N]\n"

        let const_len_part_str = format!("{}\n{}\n{}\n", bill, a.to_str_radix(16), self.consumption_table.len());
        let const_len_part = const_len_part_str.as_bytes();
        match self.provider_channel.write(&const_len_part) {
            Ok(s) => assert_eq!(s, const_len_part.len()),
            Err(e) => panic!("Failed to send the constant part of the billing info. The error was {}", e),
        };

        // send the contents of the table
        for row in &self.consumption_table {
            let string = format!("{}\n", row.signed_commitment);
            let bytes = string.as_bytes();
            match self.provider_channel.write(&bytes) {
                Ok(s) => assert_eq!(s, bytes.len()),
                Err(e) => panic!("Failed to send a signed_commitment to the provider. The error was {}", e),
            };
        }

        // empty the table
        self.consumption_table.clear();
    }
    
    /// check for new consumption messages from the meter
    pub fn read_meter_messages(&mut self) {
        customer_read_consumption(&mut self.meter_channel, &self.meter_key, &mut self.consumption_table);
    }

    /// check for price changes from the provider
    pub fn read_provider_messages(&mut self) {
        // check for new prices information
        if let Some(new_prices) = common::check_for_new_prices::<P, i32, IntegerConsumption>(&mut self.provider_channel, &self.provider_key) {
            self.prices = new_prices;
        }
    }
}

/// State associated with the provider
pub struct ProviderState<T: Read + Write> {
    /// Channel through which to communicate to the customer
    channel: T,
    /// The prices currently used to calculate the bill
    prices: Prices,
    /// Signing keys
    keys: super::Keys,
    /// Commitment parameters
    params: commitments::DHParams,
    /// Bill total
    bill_total: i64,
}

impl<T: Read + Write> ProviderState<T> {
    /// create a new ProviderState
    pub fn new(channel: T, prices: Prices, keys: super::Keys, params: commitments::DHParams) -> ProviderState<T> {
        //assert!(commitments::verify_dh_params(&params));
        ProviderState {
            channel: channel,
            prices: prices,
            keys: keys,
            params: params,
            bill_total: 0,
        }
    }

    /// for implementing BillingProtocol
    pub fn pay_bill(&mut self) -> i64 {
        let ret = self.bill_total;
        self.bill_total = 0;
        ret
    }

    /// receive new billing information
    pub fn receive_billing_information(&mut self) {
        let mut iterator = Read::by_ref(&mut self.channel).bytes();

        // get the fixed-length part
        let bill_bytes = read_up_to_newline(&mut iterator);
        let a_bytes = read_up_to_newline(&mut iterator);
        let length_bytes = read_up_to_newline(&mut iterator);

        let bill = i64::from_str_radix(&String::from_utf8(bill_bytes).unwrap(), 10).unwrap();
        let a = Mpz::from_str_radix(&String::from_utf8(a_bytes).unwrap(), 16).unwrap();
        let length = usize::from_str_radix(&String::from_utf8(length_bytes).unwrap(), 10).unwrap();

        // get all of the signed commitments
        let mut commitments = Vec::new();
        let mut others = Vec::new();

        if length == 0 {
            assert_eq!(bill, 0);
            return;
        }

        for _ in 0..length {
            let signed_commitment_bytes = read_up_to_newline(&mut iterator);
            let signed_commitment = unstringify_bytes(&String::from_utf8(signed_commitment_bytes).unwrap());
            let commitment_bytes = sign::verify(&signed_commitment, &self.keys.their_pk).unwrap();
            let commit_other_str = String::from_utf8(commitment_bytes).unwrap();

            let mut commit_other_iter = commit_other_str.split_whitespace();
            let commit_str = commit_other_iter.next().unwrap();
            let other_str = commit_other_iter.next().unwrap();
            assert_eq!(None, commit_other_iter.next());
            
            let commitment = Mpz::from_str_radix(&commit_str, 16).unwrap();
            commitments.push(commitments::Commitment::from_parts(commitment, self.params.0.clone(), false).unwrap());

            let other = usize::from_str_radix(&other_str, 10).unwrap();
            others.push(other);
        }

        // check the bill
        let expected_commit = commitments::CommitmentContext::from_opening(
            (Mpz::from(bill), a), self.params.clone()).unwrap().to_commitment();

        let mut calculated_commit = commitments[0].clone() * Mpz::from(self.prices[others[0]]);
        for i in 1..length {
            calculated_commit = calculated_commit + (commitments[i].clone() * Mpz::from(self.prices[others[i]]));
        }

        assert!(expected_commit == calculated_commit);

        // it worked so trust it
        self.bill_total += bill;
    }
    
    /// Store and send the new prices to the customer. Does not check if the prices have actually changed before sending.
    pub fn change_prices(&mut self, prices: &Prices) {
        // send them
        common::change_prices::<T, i32, IntegerConsumption>(&mut self.channel, &self.keys.my_sk, prices);

        // store the prices 
        self.prices = *prices;
    }
}

/************************************** Small tests unique to this module ***********************************************/
#[cfg(test)]
pub mod tests {
    use super::super::tests::{random_hour_of_week};
    use sodiumoxide;
    use super::super::consumption::integer_consumption::*;
    use super::super::consumption::Consumption;
    use proj_crypto::asymmetric::sign;
    use std::thread;
    use std::time::Duration;
    use std::os::unix::net::*;
    use super::super::BillingProtocol;
    use super::*;

    #[test]
    fn stringify() {
        let test_vec = vec!(0 as u8, 6, 213, 47, 8, 61, 2, 31, 2, 49, 0, 8, 71, 58, 96, 5);
        let string = stringify_bytes(&test_vec);
        let res = unstringify_bytes(&string);
        assert_eq!(res, test_vec);
    }

    #[test]
    fn meter_consume_message() {
        sodiumoxide::init();

        // random consumption to send
        let units = super::super::tests::random_positive_i32();
        //println!("Testing cons is {}", units);
        let hour = random_hour_of_week();
        let consumption = IntegerConsumption::new(units, hour);

        // channel along which to send data
        let mut channel: Vec<u8> = Vec::new();

        let params = read_or_gen_params(DEFAULT_PARAMS_PATH);
        let (pk, sk) = sign::gen_keypair();
        let mut table = Vec::new();

        // send message
        meter_consume(&params, &sk, &mut channel, &consumption);

        // receive
        customer_read_consumption(&mut channel.as_slice(), &pk, &mut table);

        // check result
        let ref row = table[0];
        assert_eq!(row.cons, units);
        assert_eq!(row.other, hour);
    }

    /************************ Stuff that is just for the impl of BillingProtocol so that the test works *********************/
    enum Role<P: Read + Write, M: Read + Write> {
        Server(ProviderState<P>),
        Client(MeterState<M>, CustomerState<P, M>),
    }
    
    /// Just for the implementation of BillingProtocol for testing purposes
    pub struct ThreeParty<T: Read + Write> {
        /// Meter, Provider or Customer
        role: Role<T, UnixStream>,
    }
    
    impl<T: Read + Write> BillingProtocol<T, i64> for ThreeParty<T> {
        type Consumption = IntegerConsumption;
        type Prices = Prices;
    
        fn null_prices() -> Self::Prices {
            [0; 7*24]
        }
    
        fn consume(&mut self, consumption: &Self::Consumption) {
            //println!("begin consume");
            // assert we are a Client
            let (ref mut meter, ref mut customer) = match self.role {
                Role::Client(ref mut m, ref mut c) => (m, c),
                _ => panic!("This function should be called on the Client"),
            };
    
            customer.read_provider_messages();
            meter.consume(consumption);
            customer.read_meter_messages();
            //println!("end consume");
        }
    
        fn send_billing_information(&mut self) {
            //println!("begin send_billing_info");
            // assert we are a Client
            let ref mut customer = match self.role {
                Role::Client(_, ref mut c) => c,
                _ => panic!("This function should be called on the Client"),
            };
    
            customer.send_billing_information();
            //println!("end send billing info");
        }
    
        fn pay_bill(&mut self) -> i64 {
            //println!("begin pay_bill");
            // assert we are a Server
            let ref mut provider = match self.role {
                Role::Server(ref mut s) => s,
                _ => panic!("This function should be called on the Server"),
            };
    
            provider.receive_billing_information();
            //println!("end pay bill");
            provider.pay_bill()
        }
    
    
        fn change_prices(&mut self, prices: &Prices) {
            //println!("begin change prices");
            // assert we are a Server
            let ref mut provider = match self.role {
                Role::Server(ref mut s) => s,
                _ => panic!("This function should be called on the Server"),
            };       
    
            provider.change_prices(prices);
            //println!("end change prices");
        }
    
        fn new_meter(provider_channel: T, prices: &Prices, keys: super::super::MeterKeys) -> ThreeParty<T> {
            let socket_path = "./meter_to_customer_test_socket".to_string();
            let socket_path_closure = socket_path.clone();
    
            let connect_thread = move || -> UnixStream {
                let mut remaining_tries = 10;
                let mut stream_option = None;
    
                while remaining_tries > 0 {
                    thread::sleep(Duration::from_millis(2));
                    let socket_path_clone = socket_path_closure.clone();
                    let result = UnixStream::connect(socket_path_clone);
                    if result.is_ok() {
                        stream_option = Some(result.unwrap());
                        break;
                    }
                    remaining_tries = remaining_tries - 1;
                };
    
                stream_option.unwrap()
            };
    
            let (m_sk, m_pk, p_pk) = match keys {
                super::super::MeterKeys::ThreeParty(ms, mp, pp) => (ms, mp, pp),
                _ => panic!("Wrong sort of MeterKeys"),
            };
            
            let listener = UnixListener::bind(socket_path).unwrap();
            let connector = thread::spawn(connect_thread);
    
            let stream1 = listener.accept().unwrap().0;
            let stream2 = connector.join().unwrap();
    
            let params = read_or_gen_params(DEFAULT_PARAMS_PATH);
            
            let meter = MeterState::new(stream1, m_sk, params.clone());
    
            let mut prices_clone = [0 as i32; 7*24];
            for i in 0..(7*24) {
                prices_clone[i] = prices[i];
            }
    
            let customer = CustomerState::new(stream2, provider_channel, prices_clone, p_pk, m_pk, params); 
    
            ThreeParty {
                role: Role::Client(meter, customer),
            }
        }
    
        fn new_server(channel: T, keys: super::super::Keys, prices: &Prices) -> ThreeParty<T> {
            let params = read_or_gen_params(DEFAULT_PARAMS_PATH);
    
            let mut prices_clone = [0 as i32; 7*24];
            for i in 0..(7*24) {
                prices_clone[i] = prices[i];
            }
            
            ThreeParty {
                role: Role::Server( ProviderState::new(channel, prices_clone, keys, params) ),
            }
        }
    }
}

