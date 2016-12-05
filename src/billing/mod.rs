//! # Contains the billing protocols I have implemented.
//!
//! Stuff common to all of the protocols is included in this file

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
    my_sk: sign::SecretKey,
    their_pk: sign::PublicKey,
}

/// Functionality which all billing protocols must provide.
///
/// The first type argument it the channel over which communication occurs. This should probably be a proj_net::{Server, Client}.
/// The second type argument is the return value of the constructors (i.e the structure implementing this trait)
pub trait BillingProtocol<T: Read + Write/*, U: BillingProtocol<T, U>*/> {
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
    fn pay_bill(&mut self) -> f64;

    /// Change the way bills are calculated. This is a message sent from the server (utility company) to the meter.
    fn change_prices(&mut self, prices: &Self::Prices);

    /// Instantiate a new meter
    fn new_meter(channel: T, prices: &Self::Prices, keys: Keys) -> Self;

    /// Instantiate a new server
    fn new_server(channel: T, keys: Keys) -> Self;
}

pub mod sign_on_meter;

#[cfg(test)]
mod tests {
    use super::sign_on_meter;
    use super::BillingProtocol;
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

    fn server_thread<T: BillingProtocol<UnixStream>, P: AsRef<Path>>(keys: super::Keys, prices: T::Prices, path: P) -> f64 {
        let listener = UnixListener::bind(path).unwrap();
        let (stream, _) = listener.accept().unwrap(); // wait for a connection from the client

        let mut server = T::new_server(stream, keys);
        
        server.change_prices(&prices);

        server.pay_bill()
    }

    fn meter_thread<T: BillingProtocol<UnixStream>, P: AsRef<Path>>(keys: super::Keys, consumption: LinkedList<T::Consumption>, path: P) {
        thread::sleep(Duration::from_millis(2)); // wait for the server to start

        let stream = UnixStream::connect(path).unwrap();
        stream.set_nonblocking(true).unwrap();

        let ref prices = &T::null_prices();

        let mut meter = T::new_meter(stream, prices, keys);

        thread::sleep(Duration::from_millis(2)); // give the server chance to send us it's new prices

        for cons in &consumption {
            meter.consume(&cons);
        }

        meter.send_billing_information();
    }

    fn test_billing_protocol<T: 'static, P: 'static>(prices: T::Prices, consumption: LinkedList<T::Consumption>, socket_path: P) -> f64
        where T: BillingProtocol<UnixStream> + Send, <T as BillingProtocol<UnixStream>>::Prices: Sync,
        <T as BillingProtocol<UnixStream>>::Consumption: Sync, <T as BillingProtocol<UnixStream>>::Consumption: Send,
        <T as BillingProtocol<UnixStream>>::Prices: Send, P: AsRef<Path> + Send + Clone + Sync
    {
        let (m_pk, m_sk) = sign::gen_keypair();
        let (s_pk, s_sk) = sign::gen_keypair();
        
        let m_keys = super::Keys {
            my_sk: m_sk,
            their_pk: s_pk,
        };

        let s_keys = super::Keys {
            my_sk: s_sk,
            their_pk: m_pk,
        };

        let socket_path_clone = socket_path.clone();
        let socket_path_clone2 = socket_path.clone();
        let server_thread = thread::spawn(|| -> f64 {server_thread::<T, P>(s_keys, prices, socket_path_clone)}); // start server
        let _ = thread::spawn(|| {meter_thread::<T, P>(m_keys, consumption, socket_path_clone2);}); // start meter

        let ret = server_thread.join().unwrap();

        // remove the socket file
        remove_file(socket_path).unwrap();

        ret
    }

    fn random_hour_of_week() -> u8 {
        let mut ret: u8;

        loop {
            ret = randombytes::randombytes(1)[0];

            if ret < ((24*7)-1) {
                break;
            }
        }

        ret
    }

    fn random_positive_f32() -> f32 {
        let mut ret: f32;

        loop {
            ret = random_f32();

            if ret > 0.0 {
                break;
            }
        }

        ret
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

            let cons = sign_on_meter::Consumption{
                hour_of_week: hour,
                units_consumed: units,
            };
            consumption.push_back(cons);

            expected_bill += prices[hour as usize] as f64 * units as f64;
        }

        let socket_path = "./sign_on_meter_test_socket".to_string();
        
        let res = test_billing_protocol::<sign_on_meter::SignOnMeter<UnixStream>, String>(prices, consumption, socket_path);

        assert_eq!(res, expected_bill);
    }

}

