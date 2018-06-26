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
use std::convert::TryInto;
use std::io;
use std::net::{SocketAddr, IpAddr};
use std::str::FromStr;

use hyper::client::connect::{Connect, Connected, Destination};
use tokio::io::{read_exact, write_all};
use tokio::net::TcpStream;
use tokio::prelude::*;

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
}

impl Connect for Socks5hProxy {
    /// The underlying transport uses TCP
    type Transport = TcpStream;
    /// Uses `std::io::Error`
    type Error = io::Error;
    /// Boxes make things simpler
    type Future = Box<Future<Item=(TcpStream, Connected), Error=io::Error> + Send>;
    /// Connects to the destination through the proxy
    /// # Parameters
    /// * `dst` - the destination to connect to
    fn connect(&self, dst: Destination) -> Self::Future {
        // Connect to the proxy
        let handshake = TcpStream::connect(&self.addr)
            // Send supported methods
            .and_then(|socket| write_all(socket, [Self::VER, 1, 0x00]))
            // Get a supported method back from the server
            .and_then(|(socket, _)| read_exact(socket, [0x00; 2]))
            // Determine if the supported method is valid
            // Check SOCKS version
            .and_then(|(socket, method)| if method[0] == Self::VER {
                // Check method
                if method[1] == 0 {
                    // Return the socket by itself
                    Ok(socket)
                }             
                else {
                    Err(io::Error::new(io::ErrorKind::Other, "server returned unsupported method"))
                }
            }
            else {
                Err(io::Error::new(io::ErrorKind::Other, "server returned unsupported SOCKS version"))
            })
            // Send the connection request
            .and_then(move |socket| {
                // Initialize the request with known values
                let mut request: Vec<u8> = vec![Self::VER, 0x01, Self::RSV];
                // Add the IP
                match IpAddr::from_str(dst.host()) {
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
                    Err(_) => {
                        request.push(0x03);
                        let host = dst.host();
                        let length: u8 = match host.len().try_into() {
                            Ok(length) => length,
                            Err(err) => return Box::<Future<Item = TcpStream, Error=io::Error> + Send>::new(future::result(
                                Err(io::Error::new(io::ErrorKind::Other, format!("invalid length for hostname: {}", err)))
                            ))
                        };
                        request.push(length);
                        request.extend(host.bytes());
                    }
                };
                // Add the port
                request.extend_from_slice(&dst.port().unwrap_or_else(|| 80).to_be().to_bytes());
                // Write the request over the socket 
                Box::<Future<Item = TcpStream, Error=io::Error> + Send>::new(write_all(socket, request).map(|(socket, _)| socket))
            })
            // Read in the first part of the response
            // VER, REP, RSV, ATYP are the same size in all responses
            .and_then(|socket| {
                read_exact(socket, [0x00; 4])
            })
            // Verify the version, reply, and reserved byte
            .and_then(|(socket, reply)| {
                // Check version
                if reply[0] != Self::VER {
                    return Err(io::Error::new(io::ErrorKind::Other, "server returned unsupported SOCKS version"))
                }
                // Check reply code
                if reply[1] != 0x00 {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("server replied with failure code {}", reply[1])))
                }
                // Check reserved byte
                if reply[2] != 0x00 {
                    return Err(io::Error::new(io::ErrorKind::Other, "server replied with invalid reserved byte"))
                }
                // TODO: Check address type is known
                // Return the socket and address type
                Ok((socket, reply[3]))
            })
            // Read in the address
            .and_then(|(socket, atyp)| {
                let address_future: Box<Future<Item=TcpStream, Error=io::Error> + Send> = match atyp {
                    // IPv4
                    0x01 => {
                        Box::new(
                            read_exact(socket, [0x00; 4])
                                .map(|(socket, _)| socket)
                        )
                    },
                    // Hostname
                    0x03 => {
                        Box::new(
                            read_exact(socket, [0x00; 1])
                                .and_then(|(socket, len)| read_exact(socket, vec![0x00; len[0] as usize]))
                                .map(|(socket, _)| socket)
                        )
                    },
                    // Ipv6
                    0x04 => {
                        Box::new(
                            read_exact(socket, [0x00; 16])
                                .map(|(socket, _)| socket)
                        )
                    }
                    // Invalid values
                    _ => {
                        Box::new(
                            future::result(
                                Err(io::Error::new(io::ErrorKind::Other, "server replied with invalid address type"))
                            )
                        )
                    }
                };
                address_future
            })
            // Read the port
            .and_then(|socket| {println!("reading port"); read_exact(socket, [0x00; 2])})
            // Strip down to only the socket and something indicating the connection was successful
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
    use hyper::Client;
    use hyper::rt::{self, Future, Stream};
    /// Tests the client using an existing local proxy on port 8080
    #[test]
    fn test_proxy() {
        let dst_addr = "http://47.52.240.125/ip".parse().unwrap();
        rt::run(fetch_url(dst_addr));
    }

    fn fetch_url(url: hyper::Uri) -> impl Future<Item=(), Error=()> {
        let proxy_addr = "127.0.0.1:9050".parse().unwrap();
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
