//! # Sign on meter
//!
//! The simplest smart meter billing protocol. This implements linear time of use billing under the assumption that everything is run on tamperproof hardware in the smart meter. This is very unrealistic.
//! The privacy issues relating to time of use billing are overcome by calculating the bill total on the meter and then only sending this total to the utility company every billing period (e.g. one month).

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
use std::io::{Read, Write, ErrorKind};
use proj_crypto::asymmetric::sign;
use std::mem::transmute;
use std::mem::drop;
use std::thread;
use std::time::Duration;

#[derive(PartialEq)]
enum Role {
    Meter,
    Server,
}

/// Co-efficient for the number of consumption units for each hour of each day of the week
pub type Prices = [f32; 24*7];

/// State of the billing protocol
pub struct SignOnMeter<T: Read + Write> {
    /// is this a server or a client?
    role: Role,
    /// The channel along which we are ending data. This should probably be used with types in proj_net
    channel: T,
    /// The running total of money still to be payed
    running_total: f64,
    /// The prices currently used to calculate the bill
    prices: Prices,
    /// Cryptographic keys for signing responses
    keys: super::Keys,
}

/// Consumption information for hourly time of use billing
#[derive(Debug)]
pub struct Consumption {
    /// The hour in the week: e.g. 7am on a Tuesday would be 24+7 hours.
    pub hour_of_week: u8,
    /// The number of units of the utility which were consumed in the last hour
    pub units_consumed: f32,
}

impl Consumption {
    /// Checks that the values stored in a Consumption object are legal
    pub fn is_valid(&self) -> bool {
        if self.hour_of_week > ((24 * 7) - 1) {
            return false;
        }

        if self.units_consumed < 0.0 {
            return false;
        }

        true
    }

    /// Instance new consumption
    pub fn new(hour_of_week: u8, units_consumed: f32) -> Consumption {
        let ret = Consumption {
            hour_of_week: hour_of_week,
            units_consumed: units_consumed,
        };

        assert!(ret.is_valid());

        ret
    }
}

impl<T: Read + Write> BillingProtocol<T> for SignOnMeter<T> {
    type Consumption = Consumption;
    type Prices = Prices;

    fn null_prices() -> Self::Prices {
        [0.0; 7*24]
    }

    fn consume(&mut self, consumption: &Self::Consumption) {
        assert!(self.role == Role::Meter);
        assert!(consumption.is_valid());

        // check for new prices information
        const BUF_LEN: usize = 4 * 7 * 24 + sign::SIGNATUREBYTES; // size_of apparently doesn't do constants
        let mut buf: [u8; BUF_LEN] = [0; BUF_LEN];

        'messages: loop { // in case several messages have been sent
            let update_prices = match self.channel.read(&mut buf) {
                Ok(s) => { assert_eq!(s, buf.len()); true },
                Err(e) => match e.kind() {
                    ErrorKind::WouldBlock => false,
                    _ => panic!("Device read failed with error {}", e),
                },
            };

            if update_prices {
                let data_buf = match sign::verify(&buf, &self.keys.their_pk) {
                    Ok(b) => b,
                    Err(_) => { drop(self); panic!("Verification of new pricing strategy failed") },
                };

                let mut new_prices: Prices = [0.0; 24*7];

                for i in 0..new_prices.len() {
                    let buf_i = i * 4;
                    let mut these_bytes = [0; 4];

                    for i in 0..4 {
                        these_bytes[i] = data_buf[buf_i + i]
                    }

                    new_prices[i] = unsafe {
                        transmute::<[u8; 4], f32>(these_bytes)
                    };

                    if new_prices[i] < 0.0 {
                        panic!("Invalid price is less than 0");
                    }
                }

                self.prices = new_prices;
            } else {
                break 'messages;
            }
        }

        // now actually work out the price
        let time = consumption.hour_of_week as usize;
        self.running_total += (self.prices[time] as f64) * (consumption.units_consumed as f64);
    }
        
    fn send_billing_information(&mut self) {
        assert!(self.role == Role::Meter);

        let buf = unsafe {
            transmute::<f64, [u8; 8]>(self.running_total)
        };

        let sbuf = sign::sign(&buf, &self.keys.my_sk);

        match self.channel.write(&sbuf) {
            Ok(s) => assert_eq!(s, sbuf.len()),
            Err(e) => panic!("Failed to write the billing information with error {}", e),
        };

        self.running_total = 0.0;
    }

    fn pay_bill(&mut self) -> f64 {
        assert!(self.role == Role::Server);

        const BUF_LEN: usize = 8 + sign::SIGNATUREBYTES; // size_of apparently doesn't output constants
        let mut buf: [u8; BUF_LEN] = [0; BUF_LEN];

        // check for any new bills that have been sent
        loop { // in case several have been sent
            match self.channel.read(&mut buf) {
                Ok(s) => assert_eq!(s, buf.len()),
                Err(e) => match e.kind() {
                    ErrorKind::TimedOut => {thread::sleep(Duration::from_secs(1)); continue},
                    _ => panic!("Device read failed with error {}", e),
                },
            };

            let data_buf = match sign::verify(&buf, &self.keys.their_pk) {
                Ok(b) => b,
                Err(_) => { drop(self); panic!("Verification of new bill failed") },
            };

            let mut new_bill_bytes = [0; 8];

            for i in 0..8 {
                new_bill_bytes[i] = data_buf[i];
            }

            let new_bill = unsafe {
                transmute::<[u8; 8], f64>(new_bill_bytes)
            };

            self.running_total += new_bill;
            break;
        }
                
        let ret = self.running_total;
        self.running_total = 0.0;
        ret
    }

    fn change_prices(&mut self, prices: &Self::Prices) {
        assert!(self.role == Role::Server);

        let buf = unsafe {
            transmute::<Prices, [u8; 4*24*7]>(*prices)
        };

        let sbuf = sign::sign(&buf, &self.keys.my_sk);

        match self.channel.write(&sbuf) {
            Ok(s) => assert_eq!(s, sbuf.len()),
            Err(e) => panic!("Failed to write the new prices with error {}", e),
        };
    }

    fn new_meter(channel: T, prices: &Prices, keys: super::Keys) -> SignOnMeter<T> {
        SignOnMeter {
            role: Role::Meter,
            channel: channel,
            running_total: 0.0,
            prices: *prices.clone(),
            keys: keys,
        }
    }

    fn new_server(channel: T, keys: super::Keys) -> SignOnMeter<T> {
        SignOnMeter {
            role: Role::Server,
            channel: channel,
            running_total: 0.0,
            prices: [0.0; 7*24],
            keys: keys,
        }
    }
}
