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

/// Functionality which all billing protocols must provide
pub trait BillingProtocol {
    /// Consumption information for billing e.g. the time of consumption and the units consumed
    type Consumption;

    /// Information used to calculate the bill (e.g. coefficients for each in which a unit could be consumed)
    type Prices;
        
    /// Consume some billed resource. Run on the meter.
    fn consume(&mut self, consumption: &Self::Consumption);

    /// Get the server up to speed with the current billing information: a message from the device to the server.
    fn send_billing_information(&mut self);

    /// Pay bill (run on the server)
    fn pay_bill(&mut self) -> f64;

    /// Change the way bills are calculated. This is a message sent from the server (utility company) to the meter.
    fn change_prices(&mut self, prices: &Self::Prices);
}

pub mod sign_on_meter;
