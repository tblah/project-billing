//! # proj_billing library crate
//!
//! This library contains some implementations of secure privacy-friendly smart meter billing protocols.
//!
//! The cryptography **has not been reviewed**.
//!
//! This project is licensed under the terms of the GNU General Public Licence as published by the Free Software Foundation, either version 3 of the licence, or (at your option) any later version published by the free software foundation (https://fsf.org).

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

#![crate_name = "proj_billing"]
#![crate_type = "lib"]
#![warn(missing_docs)]
#![warn(non_upper_case_globals)]
#![warn(non_camel_case_types)]
#![warn(unused_qualifications)]
#![feature(const_fn)]
#![feature(const_size_of)]

extern crate proj_net;
extern crate proj_crypto;
extern crate sodiumoxide;
extern crate gmp;
extern crate num;

pub mod billing;
