/*
    Copyright 2018 witchof0x20

    This file is part of sonicks.

    sonicks is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sonicks is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sonicks.  If not, see <https://www.gnu.org/licenses/>.
*/
use std::error::Error;
use std::io;

use method::Socks5Method;
use reply::Socks5Reply;

/// Generic function that builds a generic [io::Error]
#[inline]
pub fn other<E>(msg: E) -> io::Error
where
    E: Into<Box<Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, msg)
}

#[inline]
pub fn invalid_host_length(length: usize) -> io::Error {
    other(format!("invalid hostname length: {}", length))
}

#[inline]
pub fn invalid_address_type(atyp: u8) -> io::Error {
    other(format!(
        "server replied with invalid address type: {:x}",
        atyp
    ))
}
#[inline]
pub fn unsupported_method(method: Socks5Method) -> io::Error {
    other(format!(
        "server replied with method type unsupported by client: {}",
        method
    ))
}
#[inline]
pub fn unsupported_version(version: u8) -> io::Error {
    other(format!(
        "server replied with unsupported socks version: {}",
        version
    ))
}
#[inline]
pub fn unsupported_scheme(scheme: &str) -> io::Error {
    other(format!("unable to determine port for scheme: {}", scheme))
}
#[inline]
pub fn no_acceptable_methods() -> io::Error {
    other("server indicated that none of the provided methods are acceptable")
}

#[inline]
pub fn invalid_reserved(rsv: u8) -> io::Error {
    other(format!("invalid reserved byte: {}", rsv))
}
#[inline]
pub fn reply_error(reply: Socks5Reply) -> io::Error {
    // Construct the error
    other(reply.to_string())
}
