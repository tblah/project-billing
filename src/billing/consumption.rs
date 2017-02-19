//! Consumption
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

/// Co-efficient for the number of consumption units for each hour of each day of the week
pub type Prices = [f32; 24*7];

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
