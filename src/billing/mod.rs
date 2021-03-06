//! # Contains the billing protocols I have implemented.
//!
//! Stuff common to all of the protocols is included in this file
//!
//! # Example
//! ```
//! extern crate proj_billing;
//! extern crate proj_net;
//! extern crate proj_crypto;
//! extern crate sodiumoxide;
//!
//! use proj_net::server::Server;
//! use proj_net::server;
//! use proj_net::client::Client;
//! use proj_net::client;
//! use proj_net::Keypair;
//! use proj_crypto::asymmetric::key_exchange::gen_keypair;
//! use proj_crypto::asymmetric::sign;
//! use proj_crypto::asymmetric::key_id;
//! use proj_crypto::asymmetric::PublicKey ;
//! use proj_billing::billing;
//! use proj_billing::billing::sign_on_meter::SignOnMeter;
//! use proj_billing::billing::BillingProtocol;
//! use proj_billing::billing::consumption::Consumption;
//! use std::thread;
//! use std::collections::HashMap;
//! use std::time::Duration;
//! 
//! 
//! fn server_thread(sign_keys: billing::Keys, exchange_keypair: Keypair, pks: HashMap<key_id::PublicKeyId, PublicKey>,
//!                  prices: <SignOnMeter<Server> as BillingProtocol<Server, f64>>::Prices, socket: &str) -> f64 {
//!     let mut listener = server::listen(socket).unwrap();
//!     let mut stream = server::do_key_exchange(listener.incoming().next().unwrap(), &exchange_keypair, &pks).unwrap();
//!
//!     let mut server = SignOnMeter::new_server(stream, sign_keys, &prices);
//!     
//!     server.change_prices(&prices);
//!
//!     server.pay_bill()
//! }
//!
//! fn meter_thread(keys: billing::Keys, exchange_keypair: Keypair, pks: HashMap<key_id::PublicKeyId, PublicKey>,
//!                 cons: <SignOnMeter<Client> as BillingProtocol<Client, f64>>::Consumption, socket: &str) {
//!     thread::sleep(Duration::from_millis(20)); // wait for the server to start
//!
//!     let mut stream = client::start(socket, exchange_keypair, &pks).unwrap();
//!     stream.blocking_off(5);
//!
//!     let ref prices = &<SignOnMeter<Client> as BillingProtocol<Client, f64>>::null_prices();
//!
//!     let mut meter = SignOnMeter::new_meter(stream, prices, billing::MeterKeys::SignOnMeter(keys));
//!
//!     thread::sleep(Duration::from_millis(2)); // give the server chance to send us it's new prices
//!
//!     meter.consume(&cons);
//!
//!     meter.send_billing_information();
//! }
//!
//! fn main() {
//!     sodiumoxide::init();
//!     let socket_path = "127.0.0.1:1024";
//!     let (m_pk_s, m_sk_s) = sign::gen_keypair();
//!     let (s_pk_s, s_sk_s) = sign::gen_keypair();
//!     
//!     let m_keys_s = billing::Keys {
//!         my_sk: m_sk_s,
//!         their_pk: s_pk_s,
//!     };
//!
//!     let s_keys_s = billing::Keys {
//!         my_sk: s_sk_s,
//!         their_pk: m_pk_s,
//!     };
//!
//!     let m_keypair = gen_keypair();
//!     let s_keypair = gen_keypair();
//!     let mut pks = HashMap::new();
//!     pks.insert(key_id::id_of_pk(&m_keypair.0), m_keypair.0.clone());
//!     pks.insert(key_id::id_of_pk(&s_keypair.0), s_keypair.0.clone());
//!     let pks_server = pks.clone();
//!
//!     let consumption = <SignOnMeter<Client> as BillingProtocol<Client, f64>>::Consumption::new(1.0, 0);
//!
//!     let prices = [1.0; 24*7];
//!
//!     let socket_path_clone = socket_path.clone();
//!     let socket_path_clone2 = socket_path.clone();
//!     let server_thread = thread::spawn(move || -> f64 {server_thread(s_keys_s, s_keypair, pks_server, prices, socket_path_clone)});  
//!     let _ = thread::spawn(move || {meter_thread(m_keys_s, m_keypair, pks, consumption, socket_path_clone2);}); 
//!
//!     let ret = server_thread.join().unwrap();
//!
//!     assert_eq!(ret, 1.0);
//! }
//! ```

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

use std::io::prelude::*;
use proj_crypto::asymmetric::sign;

/// Cryptographic Keys
pub struct Keys {
    /// Secret key and public key
    pub my_sk: sign::SecretKey,
    /// Public Key
    pub their_pk: sign::PublicKey,
}

/// Ugly hack to make new_meter have the right parameters
pub enum MeterKeys {
    /// Argument it what it says on the tin
    SignOnMeter(Keys),
    /// (meter secret key, meter public key, provider public key)
    ThreeParty(sign::SecretKey, sign::PublicKey, sign::PublicKey),
}

/// Functionality which all billing protocols must provide.
///
/// The first type argument it the channel over which communication occurs. This should probably be a proj_net::{Server, Client}.
/// The second type argument is the return value of the constructors (i.e the structure implementing this trait)
pub trait BillingProtocol<T: Read + Write, B> {
    /// Consumption information for billing e.g. the time of consumption and the units consumed
    type Consumption;

    /// Information used to calculate the bill (e.g. coefficients for each in which a unit could be consumed)
    type Prices;

    /// returns a null Prices object
    fn null_prices() -> Self::Prices;
        
    /// To be run on the meter.
    /// This function should check for any new prices, and then add the price of consumption to the running bill
    fn consume(&mut self, consumption: &Self::Consumption);

    /// Get the server up to speed with the current billing information: a message from the device to the server.
    fn send_billing_information(&mut self);

    /// Pay bill (run on the server)
    /// This will block until it has received the billing information from the meter (via send_billing_information)
    fn pay_bill(&mut self) -> B;

    /// Change the way bills are calculated. This is a message sent from the server (utility company) to the meter.
    fn change_prices(&mut self, prices: &Self::Prices);

    /// Instantiate a new meter
    fn new_meter(channel: T, prices: &Self::Prices, keys: MeterKeys) -> Self;

    /// Instantiate a new server
    fn new_server(channel: T, keys: Keys, prices: &Self::Prices) -> Self;
}

pub mod sign_on_meter;
pub mod consumption;
pub mod three_party;
mod common;

#[cfg(test)]
mod tests {
    use super::sign_on_meter::SignOnMeter;
    use super::three_party::tests::ThreeParty;
    use super::BillingProtocol;
    use super::consumption::Consumption;
    use sodiumoxide;
    use sodiumoxide::randombytes;
    use proj_crypto::asymmetric::sign;
    use std::thread;
    use std::time::Duration;
    use std::marker::{Send, Sync};
    use std::collections::linked_list::LinkedList; // used instead of a Vec because it implements Send
    use std::path::Path;
    use std::fs::remove_file;
    use std::mem;

    // easier to use than proj_net
    use std::os::unix::net::{UnixStream, UnixListener};

    fn random_f32() -> f32 {
        let bytes = randombytes::randombytes(4);
        let mut array = [0 as u8; 4];

        for i in 0..4 {
            array[i] = bytes[i];
        }

        unsafe { mem::transmute::<[u8; 4], f32>(array) }
    }

    fn server_thread<B, T: BillingProtocol<UnixStream, B>, P: AsRef<Path>>(keys: super::Keys, prices: T::Prices, path: P) -> B {
        let listener = UnixListener::bind(path).unwrap();
        let (stream, _) = listener.accept().unwrap(); // wait for a connection from the client
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(None).unwrap(); // block indefinitely

        let mut server = T::new_server(stream, keys, &prices);
        thread::sleep(Duration::from_millis(10));
        
        server.change_prices(&prices);
        thread::sleep(Duration::from_millis(10));

        server.pay_bill()
    }

    fn meter_thread<B, T: BillingProtocol<UnixStream, B>, P: AsRef<Path> +  Clone>(keys: super::MeterKeys, consumption: LinkedList<T::Consumption>, path: P) {
        let mut remaining_tries = 10;
        let mut stream_option = None;

        while remaining_tries > 0 {
            thread::sleep(Duration::from_millis(2)); // has the server still not started?
            let path_clone = path.clone();
            let stream_result = UnixStream::connect(path_clone);
            if stream_result.is_ok() {
                stream_option = Some(stream_result.unwrap());
                break;
            }
            
            remaining_tries = remaining_tries - 1;
        };

        let stream = stream_option.unwrap(); // drop mutability, panics if we couldn't connect to the stream
        stream.set_nonblocking(true).unwrap();

        stream.set_read_timeout(None).unwrap();

        let ref prices = &T::null_prices();

        let mut meter = T::new_meter(stream, prices, keys);

        thread::sleep(Duration::from_millis(20)); // give the server chance to send us it's new prices

        for cons in &consumption {
            meter.consume(&cons);
        }

        meter.send_billing_information();
    }

    fn test_billing_protocol<T: 'static, P: 'static, B: 'static>(prices: T::Prices, consumption: LinkedList<T::Consumption>, socket_path: P, meter_keys: super::MeterKeys, s_keys: super::Keys) -> B 
        where T: BillingProtocol<UnixStream, B> + Send, <T as BillingProtocol<UnixStream, B>>::Prices: Sync,
        <T as BillingProtocol<UnixStream, B>>::Consumption: Sync, <T as BillingProtocol<UnixStream, B>>::Consumption: Send,
        <T as BillingProtocol<UnixStream, B>>::Prices: Send, P: AsRef<Path> + Send + Clone + Sync, B: Send
    {

        let socket_path_clone = socket_path.clone();
        let socket_path_clone2 = socket_path.clone();
        let server_thread = thread::spawn(|| -> B {server_thread::<B, T, P>(s_keys, prices, socket_path_clone)}); // start server
        let meter_thread = thread::spawn(|| {meter_thread::<B, T, P>(meter_keys, consumption, socket_path_clone2);}); // start meter

        let ret = server_thread.join().unwrap();
        let _ = meter_thread.join().unwrap();

        // remove the socket file
        remove_file(socket_path).unwrap();

        ret
    }

    pub fn random_hour_of_week() -> u8 {
        let mut ret: u8;

        loop {
            ret = randombytes::randombytes(1)[0];

            if ret < ((24*7)-1) {
                break;
            }
        }

        ret
    }

    pub fn random_positive_f32() -> f32 {
        let mut ret: f32;

        loop {
            ret = random_f32();

            if ret > 0.0 {
                break;
            }
        }

        ret
    }

    pub fn random_positive_i32() -> i32 {
        let bytes = sodiumoxide::randombytes::randombytes(4);
        let mut fixed_size = [0 as u8; 4];
        for i in 0..4 {
            fixed_size[i] = bytes[i];
        }
        let r = unsafe { mem::transmute::<[u8; 4], i32>(fixed_size) };
        if r > 0 { r } else { random_positive_i32() }
    }

    #[test]
    fn sign_on_meter() {
        sodiumoxide::init();
        let num_cons = randombytes::randombytes(1)[0];

        let mut prices = [0.0 as f32; 24*7];

        for i in 0..prices.len() {
            prices[i] = random_positive_f32();
        }
        
        let mut consumption = LinkedList::new();
        let mut expected_bill = 0.0;

        for _ in 0..num_cons {
            let units = random_positive_f32();
            let hour = random_hour_of_week();

            let cons = <SignOnMeter<UnixStream> as BillingProtocol<UnixStream, f64>>::Consumption::new(units, hour);
            consumption.push_back(cons);

            expected_bill += prices[hour as usize] as f64 * units as f64;
        }

        let socket_path = "./sign_on_meter_test_socket".to_string();

        let (m_pk, m_sk) = sign::gen_keypair();
        let (s_pk, s_sk) = sign::gen_keypair();

        let s_keys = super::Keys {
            my_sk: s_sk,
            their_pk: m_pk,
        };
       
        let m_keys = super::Keys {
            my_sk: m_sk,
            their_pk: s_pk,
        };

        let res = test_billing_protocol::<SignOnMeter<UnixStream>, String, f64>(prices, consumption, socket_path, super::MeterKeys::SignOnMeter(m_keys), s_keys);

        assert_eq!(res, expected_bill);
    }

    #[test]
    fn three_party() {
        sodiumoxide::init();
        let num_cons = 1 + randombytes::randombytes(1)[0] % 9;

        let mut prices = [0 as i32; 24*7];

        for i in 0..(24*7) {
            prices[i as usize] = random_positive_i32();
        }

        let mut consumption = LinkedList::new();
        let mut expected_bill = 0 as i64;

        for _ in 0..num_cons {
            let units = random_positive_i32() >> 20; // make it smaller so we don't overflow the bill
            let hour = random_hour_of_week() as u64;

            let cons = <ThreeParty<UnixStream> as BillingProtocol<UnixStream, i64>>::Consumption::new(units, hour);
            consumption.push_back(cons);

            expected_bill += prices[hour as usize] as i64 * units as i64;
        }

        let socket_path = "./three_party_test_socket".to_string();

        let (m_pk, m_sk) = sign::gen_keypair();
        let (s_pk, s_sk) = sign::gen_keypair();

        let s_keys = super::Keys {
            my_sk: s_sk,
            their_pk: m_pk.clone(),
        };

        let res = test_billing_protocol::<ThreeParty<UnixStream>, String, i64>(prices, consumption, socket_path,
                                                                  super::MeterKeys::ThreeParty(m_sk, m_pk, s_pk), s_keys);
        remove_file("meter_to_customer_test_socket").unwrap();

        assert_eq!(res, expected_bill);
    }
}

