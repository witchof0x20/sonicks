use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Socks5Reply {
    /// X'00' succeeded
    Succeeded,
    /// X'01' general SOCKS server failure
    GeneralFailure,
    /// X'02' connection not allowed by ruleset
    NotAllowedRuleset,
    /// X'03' Network unreachable
    NetworkUnreachable,
    /// X'04' Host unreachable
    HostUnreachable,
    /// X'05' Connection refused
    ConnectionRefused,
    /// X'06' TTL expired
    TtlExpired,
    /// X'07' Command not supported
    CommandNotSupported,
    /// X'08' Address type not supported
    AddressTypeNotSupported,
    /// X'09' to X'FF' unassigned
    Unassigned(u8),
}

impl Into<u8> for Socks5Reply {
    /// Converts a [Socks5Reply] into a [u8]
    fn into(self) -> u8 {
        match self {
            Socks5Reply::Succeeded => 0x00,
            Socks5Reply::GeneralFailure => 0x01,
            Socks5Reply::NotAllowedRuleset => 0x02,
            Socks5Reply::NetworkUnreachable => 0x03,
            Socks5Reply::HostUnreachable => 0x04,
            Socks5Reply::ConnectionRefused => 0x05,
            Socks5Reply::TtlExpired => 0x06,
            Socks5Reply::CommandNotSupported => 0x07,
            Socks5Reply::AddressTypeNotSupported => 0x08,
            Socks5Reply::Unassigned(code) => code,
        }
    }
}
impl From<u8> for Socks5Reply {
    /// Converts a [u8] into a [Socks5Reply]
    ///
    /// # Parameters
    /// * `byte` - the byte to convert
    fn from(byte: u8) -> Socks5Reply {
        match byte {
            0x00 => Socks5Reply::Succeeded,
            0x01 => Socks5Reply::GeneralFailure,
            0x02 => Socks5Reply::NotAllowedRuleset,
            0x03 => Socks5Reply::NetworkUnreachable,
            0x04 => Socks5Reply::HostUnreachable,
            0x05 => Socks5Reply::ConnectionRefused,
            0x06 => Socks5Reply::TtlExpired,
            0x07 => Socks5Reply::CommandNotSupported,
            0x08 => Socks5Reply::AddressTypeNotSupported,
            code => Socks5Reply::Unassigned(code),
        }
    }
}

impl fmt::Display for Socks5Reply {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message: String = match *self {
            Socks5Reply::Succeeded => "succeeded".into(),
            Socks5Reply::GeneralFailure => "general SOCKS server failure".into(),
            Socks5Reply::NotAllowedRuleset => "connection not allowed by ruleset".into(),
            Socks5Reply::NetworkUnreachable => "network unreachable".into(),
            Socks5Reply::HostUnreachable => "host unreachable".into(),
            Socks5Reply::ConnectionRefused => "connection refused".into(),
            Socks5Reply::TtlExpired => "TTL expired".into(),
            Socks5Reply::CommandNotSupported => "command not supported".into(),
            Socks5Reply::AddressTypeNotSupported => "address type not supported".into(),
            Socks5Reply::Unassigned(code) => format!("Unassigned reply {:X}", code),
        };
        f.write_str(&message)
    }
}
