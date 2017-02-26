//! Integer Consumption
//!
//! Billing Protocol allows protocols to define their own pricing strategy. This module implements an example pricing strategy: hourly time of use billing.
//!

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

use super::Consumption;
use std::mem::{transmute, transmute_copy};

/// Co-efficient for the number of consumption units for each hour of each day of the week
pub type Prices = [i32; 24*7];

/// Consumption information for hourly time of use billing
#[derive(Debug)]
pub struct IntegerConsumption {
    /// The hour in the week: e.g. 7am on a Tuesday would be 24+7 hours.
    pub hour_of_week: u8,
    /// The number of units of the utility which were consumed in the last hour
    pub units_consumed: i32,
}

impl Consumption<i32, u8> for IntegerConsumption {
    type Prices = Prices;
    
    /// Checks that the values stored in a Consumption object are legal
    fn is_valid(&self) -> bool {
        if self.hour_of_week > ((24 * 7) - 1) {
            return false;
        }

        if self.units_consumed < 0 {
            return false;
        }

        true
    }

    /// Instance new consumption
    fn new(cons: i32, other: u8) -> IntegerConsumption {
        let ret = IntegerConsumption {
            hour_of_week: other,
            units_consumed: cons,
        };

        assert!(ret.is_valid());

        ret
    }

    fn null_prices() -> Prices { [0; 24*7] }

    fn set_price(prices: &mut Prices, other: u8, price: i32) { prices[other as usize] = price }

    fn get_price(prices: &Prices, other: u8) -> i32 { prices[other as usize] }

    fn prices_len() -> usize {24*7}

    fn cons_from_bytes(bytes: &[u8]) -> i32 {
        assert!(bytes.len() == 4);
        let mut fixed_size = [0 as u8; 4];

        for i in 0..4 {
            fixed_size[i] = bytes[i];
        }

        unsafe { transmute::<[u8; 4], i32>(fixed_size) }
    }

    fn prices_from_bytes(bytes: &[u8]) -> Prices {
        assert!(bytes.len() == 24*7*4);
        let mut fixed_size = [0 as u8; 24*7*4];

        for i in 0..(24*7*4) {
            fixed_size[i] = bytes[i];
        }

        unsafe { transmute::<[u8; 24*7*4], Prices>(fixed_size) }
    }

    fn prices_to_bytes(prices: &Prices) -> Vec<u8> {
        let array = unsafe { transmute_copy::<Prices, [u8; 24*7*4]>(prices) };
        Vec::<u8>::from(array.as_ref())
    }
}
