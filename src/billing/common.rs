//! Stuff common to several billing protocols (DRY)

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
use num::cast::NumCast;
use proj_crypto::asymmetric::sign;
use std::io::{Read, Write, ErrorKind};
use super::consumption::Consumption;
use std::time::SystemTime;
use std::vec::Vec;
use std::mem::{size_of, transmute};

// only works for 4-byte wide Cons (see the transmute)
pub fn check_for_new_prices<T: Read + Write, Cons: Sized, Other: NumCast, C: Consumption<Cons, Other>>(channel: &mut T, their_pk: &sign::PublicKey) -> Option<C::Prices> {
    const BUF_LEN: usize = 4 * 7 * 24 + sign::SIGNATUREBYTES + size_of::<SystemTime>(); 
    let mut buf: [u8; BUF_LEN] = [0; BUF_LEN];
    let mut ret = None;

    loop { // in case several messages have been sent
        match channel.read(&mut buf) {
            Ok(s) => { assert_eq!(s, buf.len()) },
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock => break,
                _ => panic!("Device read failed with error {}", e),
            },
        }

        let mut time_buf = match sign::verify(&buf, their_pk) {
            Ok(b) => b,
            Err(_) => { panic!("Verification of new pricing strategy failed") },
        };

        // split timestamp and prices
        let data_buf = time_buf.split_off(size_of::<SystemTime>());

        // check timestamp
        let mut timestamp_bytes: [u8; size_of::<SystemTime>()] = [0; size_of::<SystemTime>()];
        for i in 0..size_of::<SystemTime>() {
            timestamp_bytes[i] = time_buf[i];
        }
        let timestamp: SystemTime = unsafe {
            transmute::<[u8; size_of::<SystemTime>()], SystemTime>(timestamp_bytes)
        };
        let time_difference = SystemTime::now().duration_since(timestamp).unwrap();
        // expect new prices every 2 months
        if time_difference.as_secs() > (2 * 31 * 24 * 60 * 60) {
            panic!("Time difference is too large");
        } // else everything's good

        let mut new_prices: C::Prices = C::null_prices();

        for i in 0..C::prices_len() {
            let buf_i = i * 4;
            let mut these_bytes = [0; 4];

            for i in 0..4 {
                these_bytes[i] = data_buf[buf_i + i]
            }

            let new_price = C::cons_from_bytes(&these_bytes);
            C::set_price(&mut new_prices, Other::from(i).unwrap(), new_price);
        }

        ret = Some(new_prices);
    }

    ret
}

pub fn change_prices<T: Write, Cons, Other, C: Consumption<Cons, Other>>(channel: &mut T, sk: &sign::SecretKey, prices: &C::Prices) {
    // get timestamp
    let now = SystemTime::now();
    let time_buf = unsafe {
        transmute::<SystemTime, [u8; size_of::<SystemTime>()]>(now)
    };

    // get prices
    let mut price_buf = C::prices_to_bytes(prices);

    // timestamp, prices
    let mut buf: Vec<u8> = Vec::new();
    // to get the lengths equal
    for _ in 0..size_of::<SystemTime>() {
        buf.push(0);
    }

    buf.copy_from_slice(&time_buf);
    buf.append(&mut price_buf);

    let sbuf = sign::sign(&buf, sk);

    match channel.write(&sbuf) {
        Ok(s) => assert_eq!(s, sbuf.len()),
        Err(e) => panic!("Failed to write the new prices error {}", e),
    };
}

