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

use std::mem::transmute;
use proj_crypto::asymmetric::sign;
use std::io::{Read, Write, ErrorKind};
use super::consumption::*;

pub fn check_for_new_prices<T: Read + Write>(channel: &mut T, their_pk: &sign::PublicKey) -> Option<Prices> {
    const BUF_LEN: usize = 4 * 7 * 24 + sign::SIGNATUREBYTES; // size_of apparently doesn't do constants
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

        let data_buf = match sign::verify(&buf, their_pk) {
            Ok(b) => b,
            Err(_) => { panic!("Verification of new pricing strategy failed") },
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

        ret = Some(new_prices);
    }

    ret
}

pub fn change_prices<T: Read + Write>(channel: &mut T, sk: &sign::SecretKey, prices: &Prices) {
    let buf = unsafe {
        transmute::<Prices, [u8; 4*24*7]>(*prices)
    };

    let sbuf = sign::sign(&buf, sk);

    match channel.write(&sbuf) {
        Ok(s) => assert_eq!(s, sbuf.len()),
        Err(e) => panic!("Failed to write the new prices error {}", e),
    };
}

