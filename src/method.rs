use std::fmt;

/// The method negotiated at handshake
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Socks5Method {
    ///  X'00' NO AUTHENTICATION REQUIRED
    NoAuthRequired,
    /// X'01' GSSAPI
    Gssapi,
    /// X'02' USERNAME/PASSWORD
    UsernamePassword,
    /// X'03' to X'7F' IANA ASSIGNED
    IanaAssigned(u8),
    /// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    Private(u8),
    /// X'FF' NO ACCEPTABLE METHODS
    NoAcceptable,
}
impl Into<u8> for Socks5Method {
    /// Converts a Socks5Method into its byte form
    fn into(self) -> u8 {
        match self {
            Socks5Method::NoAuthRequired => 0x00,
            Socks5Method::Gssapi => 0x01,
            Socks5Method::UsernamePassword => 0x02,
            Socks5Method::IanaAssigned(code) => code,
            Socks5Method::Private(code) => code,
            Socks5Method::NoAcceptable => 0xFF,
        }
    }
}
impl From<u8> for Socks5Method {
    /// Converts a byte into a Socks5Method
    /// # Parameters
    /// * `byte` - the byte to read from
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Socks5Method::NoAuthRequired,
            0x01 => Socks5Method::Gssapi,
            0x02 => Socks5Method::UsernamePassword,
            code @ 0x03...0x7F => Socks5Method::IanaAssigned(code),
            code @ 0x80...0xFE => Socks5Method::Private(code),
            0xFF => Socks5Method::NoAcceptable,
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for Socks5Method {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message: String = match *self {
            Socks5Method::NoAuthRequired => "NO AUTHENTICATION REQUIRED".into(),
            Socks5Method::Gssapi => "GSSAPI".into(),
            Socks5Method::UsernamePassword => "USERNAME/PASSWORD".into(),
            Socks5Method::IanaAssigned(code) => format!("IANA ASSIGNED METHOD {:X}", code),
            Socks5Method::Private(code) => format!("PRIVATE METHOD {:X}", code).into(),
            Socks5Method::NoAcceptable => "NO ACCEPTABLE METHODS".into(),
        };
        f.write_str(&message)
    }
}
