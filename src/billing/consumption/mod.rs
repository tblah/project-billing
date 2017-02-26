//! Consumption schemes

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

pub mod floating_consumption;
pub mod integer_consumption;

/// Note that Cons doubles as the type of the price per cons, just to keep things simple
pub trait Consumption<Cons, Other> {
    /// Co-efficients for the number of consumption units for each hour of day each week
    type Prices;

    /// Instance new HourlyConsumption
    fn new(cons: Cons, other: Other) -> Self;

    /// Check the validity of an HourlyConsumption
    fn is_valid(&self) -> bool;

    /// Make an empty prices object
    fn null_prices() -> Self::Prices;

    /// Set Price for a particular other
    fn set_price(prices: &mut Self::Prices, other: Other, price: Cons);

    /// Get Price of a particular other
    fn get_price(prices: &Self::Prices, other: Other) -> Cons;

    /// Length of a Prices
    fn prices_len() -> usize;

    /// Cons from raw bytes
    fn cons_from_bytes(bytes: &[u8]) -> Cons;

    /// Prices from raw bytes
    fn prices_from_bytes(bytes: &[u8]) -> Self::Prices;

    /// Prices to raw bytes
    fn prices_to_bytes(prices: &Self::Prices) -> Vec<u8>;
}
