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
use std::convert::{Into, TryInto};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use hyper::client::connect::{Connect, Connected, Destination};
use tokio::io::{read_exact, write_all};
use tokio::net::TcpStream;
use tokio::prelude::*;

use error;
use method::Socks5Method;
use reply::Socks5Reply;

/// A SOCKS5 proxy
///
/// Does DNS resolution remotely (socks5h)
pub struct Socks5hProxy {
    addr: SocketAddr,
}

impl Socks5hProxy {
    /// The SOCKS version this object supports
    const VER: u8 = 5;
    /// The reserved byte (must always be zero)
    const RSV: u8 = 0;
    /// Constructor for the proxy
    ///
    /// # Parameters
    /// * `addr` - address of the proxy
    pub fn new(addr: SocketAddr) -> Self {
        Socks5hProxy { addr }
    }
    /// Sends the initial method negotiation handshake
    /// # Parameters
    /// * `socket` - the socket to send and receive the handshake over
    fn method_handshake(socket: TcpStream) -> impl Future<Item=(TcpStream, u8, Socks5Method), Error=io::Error> {
        // Send the supported methods
        write_all(socket, [Self::VER, 1, Socks5Method::NoAuthRequired.into()])
            // Remove the extra field
            .and_then(|(socket, _)| read_exact(socket, [0x00; 2]))
            .and_then(|(socket, method_resp)| future::ok((socket, method_resp[0], method_resp[1].into())))
    }

}

impl Connect for Socks5hProxy {
    /// The underlying transport uses TCP
    type Transport = TcpStream;
    /// Uses `std::io::Error`
    type Error = io::Error;
    /// Boxes make things simpler
    type Future = Box<Future<Item = (TcpStream, Connected), Error = io::Error> + Send>;
    /// Connects to the destination through the proxy
    /// # Parameters
    /// * `dst` - the destination to connect to
    fn connect(&self, dst: Destination) -> Self::Future {
        // Connect to the proxy
        let handshake = TcpStream::connect(&self.addr)
            // Send supported methods and receive a method/version back
            .and_then(|socket| Self::method_handshake(socket))
            // Check the method and version
            .and_then(|(socket, version, method)| match (version, method) {
                // No authentication 
                (Self::VER, Socks5Method::NoAuthRequired) => Ok(socket),
                // TODO: user/pass auth and GSSAPI
                // Specific error for when no acceptable methods are returned
                (Self::VER, Socks5Method::NoAcceptable) => Err(error::no_acceptable_methods()),
                // Unsupported method
                (Self::VER, method) => Err(error::unsupported_method(method)),
                // Unsupported SOCKS version
                (version, _) => Err(error::unsupported_version(version))
            })
            // Send the connection request
            .and_then(move |socket| {
                // Initialize the request with known values
                let mut request: Vec<u8> = vec![Self::VER, 0x01, Self::RSV];
                // Try to parse the destination as an IP address
                match IpAddr::from_str(dst.host()) {
                    // If the parsing works
                    Ok(ip) => match ip  {
                        IpAddr::V4(ip) => {
                            request.push(0x01);
                            request.extend_from_slice(&ip.octets());
                        },
                        IpAddr::V6(ip) => {
                            request.push(0x04);
                            request.extend_from_slice(&ip.octets());
                        }
                    },
                    // If the parsing fails, treat the
                    // destination as a hostname
                    Err(_) => {
                        request.push(0x03);
                        // Extract the hostname from the destination
                        let host = dst.host();
                        // Ensure the host's length is compliant
                        let length: u8 = match host.len().try_into() {
                            // Zero-length or too long
                            Ok(0) | Err(_) => 
                                return Err(error::invalid_host_length(host.len())),
                            // Normal case
                            Ok(length) => length,
                        };
                        // Add the length byte to the request
                        request.push(length);
                        // Add the hostname as bytes to the request
                        request.extend(host.bytes());
                    }
                };
                // Get the port
                let port = match dst.port() {
                    Some(port) => port,
                    // If the port is not specified, use
                    // the scheme to determine it
                    None => match dst.scheme() {
                        "http" => 80,
                        "https" => 443,
                        scheme => return Err(error::unsupported_scheme(scheme))
                    }
                };
                // Add the port
                request.extend_from_slice(
                    &port
                        .to_be()
                        .to_bytes()
                );
                // Write the request over the socket 
                Ok(write_all(socket, request).map(|(socket, _)| socket))
            })
            // Result here is a future of a future, so we need to flatten it
            .flatten()
            // Read in the first part of the response
            // VER, REP, RSV, ATYP are the same size in all responses
            .and_then(|socket| {
                read_exact(socket, [0x00; 4])
            })
            // Verify the version, reply, and reserved byte
            .and_then(|(socket, response)| {
                // Check version
                if response[0] != Self::VER {
                    return Err(error::unsupported_version(response[0]))
                }
                // Check the reply code
                let reply = response[1].into();
                if reply != Socks5Reply::Succeeded {
                    return Err(error::reply_error(reply))
                }
                // Check reserved byte
                if response[2] != Self::RSV { 
                    return Err(error::invalid_reserved(response[2]))
                }
                // TODO: Check address type is known
                // Return the socket and address type
                Ok((socket, response[3]))
            })
            // Read in the address
            .and_then(|(socket, atyp)| {
                let address_future: Box<Future<Item=TcpStream, Error=io::Error> + Send> = match atyp {
                    // IPv4
                    0x01 => {
                        // Create the future to read an IPV4 address
                        let fut = read_exact(socket, [0x00; 4])
                            .map(|(socket, _)| socket);
                        // Box it
                        Box::new(fut)
                    },
                    // Hostname
                    0x03 => {
                        // Create the future to read the hostname
                        let fut = read_exact(socket, [0x00; 1])
                            .and_then(|(socket, len)|
                                read_exact(socket, vec![0x00; len[0] as usize])
                            )
                            .map(|(socket, _)| socket);
                        // Box it
                        Box::new(fut)
                    },
                    // Ipv6
                    0x04 => {
                        // Create the future to read an IPV6 address
                        let fut = read_exact(socket, [0x00; 16])
                            .map(|(socket, _)| socket);
                        // Box it
                        Box::new(fut)
                    }
                    // Invalid values
                    atyp => {
                        // Create an error
                        let err = error::invalid_address_type(atyp);
                        // Box it
                        Box::new(future::err(err))
                    }
                };
                address_future
            })
            // Read the port
            .and_then(|socket| read_exact(socket, [0x00; 2]))
            // Strip down to only the socket and something
            // indicating the connection was successful
            .map(|(socket, _)| (socket, Connected::new()));
        // Box up the handshake
        Box::new(handshake)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env;
    use std::io::{self, Write};

    use hyper;
    use hyper::rt::{self, Future, Stream};
    use hyper::Client;
    /// Tests the client using an existing local proxy on port 8080
    #[test]
    fn test_proxy() {
        let dst_addr = "http://httpbin.net/ip".parse().unwrap();
        rt::run(fetch_url(dst_addr));
    }

    fn fetch_url(url: hyper::Uri) -> impl Future<Item = (), Error = ()> {
        let proxy_addr = "192.168.0.9:8080".parse().unwrap();
        let proxy = Socks5hProxy::new(proxy_addr);
        let client: Client<Socks5hProxy, hyper::Body> = Client::builder().build(proxy);

        client
            // Fetch the url...
            .get(url)
            // And then, if we get a response back...
            .and_then(|res| {
                println!("Response: {}", res.status());
                println!("Headers: {:#?}", res.headers());

                // The body is a stream, and for_each returns a new Future
                // when the stream is finished, and calls the closure on
                // each chunk of the body...
                res.into_body().for_each(|chunk| {
                    io::stdout().write_all(&chunk)
                        .map_err(|e| panic!("example expects stdout is open, error={}", e))
                })
            })
            // If all good, just tell the user...
            .map(|_| {
                println!("\n\nDone.");
            })
            // If there was an error, let the user know...
            .map_err(|err| {
                eprintln!("Error {}", err);
            })
    }
}
