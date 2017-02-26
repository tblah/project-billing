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

use super::BillingProtocol;
use super::consumption::*;
use super::common;
use std::io::{Read, Write};
use proj_crypto::asymmetric::{sign, commitments};
use std::thread;
use std::time::Duration;
use std::os::unix::net::*;
use std::mem::transmute;
use gmp::mpz::Mpz;
use std::io;
use std::path::Path;

/// The default file to store diffie-hellman parameters in
pub static DEFAULT_PARAMS_PATH: &'static str = "dhparams.txt";

/// Try to read DHParams from the provided file. If this fails, then generate new parameters and write these to the file
pub fn read_or_gen_params<P: AsRef<Path> + Clone>(path: P) -> commitments::DHParams {
    match commitments::read_dhparams(path.clone()) {
        Ok(params) => params,
        Err(e) => {
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
    /// Signing keys
    keys: super::Keys,
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
fn meter_consume<W: Write>(params: &commitments::DHParams, sk: &sign::SecretKey, channel: &mut W, consumption: &Consumption) {
    assert!(consumption.is_valid());

    let cons_int = unsafe {transmute::<f32, u32>(consumption.units_consumed)};

    let a = commitments::random_a(&params.1);
    let a_str = a.to_str_radix(16);

    let commit_context = commitments::CommitmentContext::from_opening((Mpz::from(cons_int), a), params.clone()).unwrap();
    let commitment = commit_context.to_commitment();
    let commitment_str = commitment.x.to_str_radix(16);

    // send (cons, other, a) + sign(commit)

    let touple_str = format!("{} {} {}", cons_int, consumption.hour_of_week, a_str);
    let signed_commitment = sign::sign(&commitment_str.as_bytes(), &sk);

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

    // unstringify the signed commitment
    let signed_commitment = unstringify_bytes(&String::from_utf8(signed_commitment_str_bytes).unwrap());

    // verify the signature on the commitment
    let commitment_bytes = sign::verify(&signed_commitment, meter_key).unwrap();
    let commit_str = String::from_utf8(commitment_bytes).unwrap();

    // touple looks like "cons other a"
    let mut touple_iter = touple_str.split_whitespace();
    let cons_str = touple_iter.next().unwrap();
    let other_str = touple_iter.next().unwrap();
    let a_str = touple_iter.next().unwrap();
    assert_eq!(None, touple_iter.next());

    let cons_int = u32::from_str_radix(&cons_str, 10).unwrap();
    let other = u8::from_str_radix(&other_str, 10).unwrap();
    let commit = Mpz::from_str_radix(&commit_str, 16).unwrap();
    let a = Mpz::from_str_radix(&a_str, 16).unwrap();

    let cons = unsafe{ transmute::<u32, f32>(cons_int) };

    let table_row = ConsumptionTableRow {
        signed_commitment: signed_commitment,
        cons: cons,
        other: other,
        commit: commit,
        a: a,
    };
        
    table.push(table_row);
}
    
impl<T: Read + Write> MeterState<T> {
    /// Create a new MeterState object
    pub fn new(channel: T, keys: super::Keys, params: commitments::DHParams) -> MeterState<T> {
        assert!(commitments::verify_dh_params(&params));
        MeterState {
            channel: channel,
            keys: keys,
            params: params
        }
    }

    /// Called once every hour with the consumption incurred in that hour
    pub fn consume(&mut self, consumption: &Consumption) {
        meter_consume(&self.params, &self.keys.my_sk, &mut self.channel, consumption);
    }
}

struct ConsumptionTableRow {
    signed_commitment: Vec<u8>,
    cons: f32,
    other: u8,
    commit: Mpz,
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
        assert!(commitments::verify_dh_params(&params));
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
    
    /// check for new consumption messages from the meter
    pub fn read_meter_messages(&mut self) {
        customer_read_consumption(&mut self.meter_channel, &self.meter_key, &mut self.consumption_table);
    }

    /// check for price changes from the provider
    pub fn read_provider_messages(&mut self) {
        // check for new prices information
        if let Some(new_prices) = common::check_for_new_prices(&mut self.provider_channel, &self.provider_key) {
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
}

impl<T: Read + Write> ProviderState<T> {
    /// create a new ProviderState
    pub fn new(channel: T, prices: Prices, keys: super::Keys, params: commitments::DHParams) -> ProviderState<T> {
        assert!(commitments::verify_dh_params(&params));
        ProviderState {
            channel: channel,
            prices: prices,
            keys: keys,
            params: params,
        }
    }
    
    /// Store and send the new prices to the customer. Does not check if the prices have actually changed before sending.
    pub fn change_prices(&mut self, prices: &Prices) {
        // send them
        common::change_prices(&mut self.channel, &self.keys.my_sk, prices);

        // store the prices 
        self.prices = *prices;
    }
}

/************************************** Small tests unique to this module ***********************************************/
#[cfg(test)]
mod tests {
    use super::super::tests::{random_positive_f32, random_hour_of_week};
    use sodiumoxide;
    use super::super::consumption::Consumption;
    use proj_crypto::asymmetric::{sign, commitments};

    #[test]
    fn stringify() {
        let test_vec = vec!(0 as u8, 6, 213, 47, 8, 61, 2, 31, 2, 49, 0, 8, 71, 58, 96, 5);
        let string = super::stringify_bytes(&test_vec);
        let res = super::unstringify_bytes(&string);
        assert_eq!(res, test_vec);
    }

    #[test]
    fn meter_consume_message() {
        sodiumoxide::init();

        // random consumption to send
        let units = random_positive_f32();
        let hour = random_hour_of_week();
        let consumption = Consumption::new(hour, units);

        // channel along which to send data
        let mut channel: Vec<u8> = Vec::new();

        let params = super::read_or_gen_params(super::DEFAULT_PARAMS_PATH);
        let (pk, sk) = sign::gen_keypair();
        let mut table = Vec::new();

        // send message
        super::meter_consume(&params, &sk, &mut channel, &consumption);

        // receive
        super::customer_read_consumption(&mut channel.as_slice(), &pk, &mut table);

        // check result
        let ref row = table[0];
        assert_eq!(row.cons, units);
        assert_eq!(row.other, hour);
    }
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

/*impl<T: Read + Write> BillingProtocol<T> for ThreeParty<T> {
    type Consumption = Consumption;
    type Prices = Prices;

    fn null_prices() -> Self::Prices {
        [0.0; 7*24]
    }

    fn consume(&mut self, consumption: &Self::Consumption) {
        // assert we are a Client
        assert!( match self.role { Role::Client(_,_) => true, _ => false } );
    }
}*/

