//! The free-roam wire format (magic MC3R), as xboxrecomp/src/net/roam/roam_core.h defines it: the datagrams between
//! the roam core in the game and the free-roam hub.  Moved here from crates/server/roam so the client side can share
//! it once the core is ported to Rust.  Code after nfsu2-web's roam hub (MIT License, Copyright (c) 2026 th0mk).

pub const ROAM_PORT: u16 = 47210;
pub const MAGIC: &[u8; 4] = b"MC3R";
pub const HDR: usize = 16;
pub const CRC: usize = 4;
pub const MSG_HELLO: u8 = 1;
pub const MSG_PEERS: u8 = 2;
pub const MSG_SNAP: u8 = 3;
pub const MSG_BYE: u8 = 8;
pub const MSG_FAR: u8 = 9;
pub const HF_CREW: u16 = 0x0200;
pub const ST_ROAM: u8 = 2;
pub const LIST_MAX: usize = 96;
/// FAR entries per datagram at most: 50 bytes each at worst, one datagram under 1200 bytes
pub const FAR_PART: usize = 20;
/// FAR entries per list (a city) at most, over ceil(n / FAR_PART) datagrams
pub const FAR_MAX: usize = 256;


pub fn crc32(d: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in d {
        c ^= b as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(c & 1));
        }
    }
    !c
}

#[derive(Clone, Debug, PartialEq)]
pub enum Msg {
    Hello { sender: u32, status: u8, name: String, links: u8, room: u32 },
    Snap { sender: u32, status: u8, p: [f32; 3], v: [f32; 3], q: [i16; 4] },
    Bye { sender: u32 },
    Other,
}

struct Rd<'a> {
    d: &'a [u8],
    n: usize,
}
impl Rd<'_> {
    fn take(&mut self, k: usize) -> Option<&[u8]> {
        let s = self.d.get(self.n..self.n + k)?;
        self.n += k;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn f32(&mut self) -> Option<f32> {
        self.u32().map(f32::from_bits)
    }
}

/// A datagram to the hub: header, CRC and the fields the hub reads (None: not one of ours, or malformed).
pub fn decode(d: &[u8]) -> Option<Msg> {
    if d.len() < HDR + CRC || &d[..4] != MAGIC || d[4] != 1 || u16::from_le_bytes([d[6], d[7]]) as usize != d.len() {
        return None;
    }
    let body = &d[..d.len() - CRC];
    if crc32(body) != u32::from_le_bytes(d[d.len() - 4..].try_into().ok()?) {
        return None;
    }
    let mut r = Rd { d: body, n: 8 };
    let (sender, _seq, flags) = (r.u32()?, r.u16()?, r.u16()?);
    if sender == 0 {
        return None;
    }
    Some(match d[5] {
        MSG_HELLO => {
            let (_core, _plat, status, _port, _cfg, room) = (r.u16()?, r.u8()?, r.u8()?, r.u16()?, r.u16()?, r.u32()?);
            let nl = r.u8()? as usize;
            let name = r.take(nl)?;
            if nl > 24 || name.iter().any(|&c| !(0x20..0x7F).contains(&c)) {
                return None;
            }
            let name: String = name.iter().map(|&c| c as char).collect();
            let seen = r.u8()? as usize;
            r.take(4 * seen)?;
            let mut links = 0;
            if flags & HF_CREW != 0 && r.n < body.len() {
                let crews = r.u8()? as usize;
                r.take(4 * crews)?;
                links = r.u8().unwrap_or(0);
            }
            Msg::Hello { sender, status, name, links, room }
        }
        MSG_SNAP => {
            let (status, _epoch, _cfg, n, _clock) = (r.u8()?, r.u8()?, r.u16()?, r.u8()?, r.u8()?);
            if n == 0 {
                return None;
            }
            let _t = r.u32()?;
            let p = [r.f32()?, r.f32()?, r.f32()?];
            let v = [r.f32()?, r.f32()?, r.f32()?];
            if p.iter().chain(&v).any(|x| !x.is_finite() || x.abs() > 20000.0) {
                return None;
            }
            let q = [r.u16()? as i16, r.u16()? as i16, r.u16()? as i16, r.u16()? as i16];
            Msg::Snap { sender, status, p, v, q }
        }
        MSG_BYE => Msg::Bye { sender },
        _ => Msg::Other,
    })
}

/// A PEERS datagram: (virtual address, port, id) each, the address big-endian.
pub fn encode_peers(sender: u32, seq: u16, list: &[(u32, u16, u32)]) -> Vec<u8> {
    let n = list.len().min(LIST_MAX);
    let len = HDR + 1 + 10 * n + CRC;
    let mut b = Vec::with_capacity(len);
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&[1, MSG_PEERS]);
    b.extend_from_slice(&(len as u16).to_le_bytes());
    b.extend_from_slice(&sender.to_le_bytes());
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(&[0, 0]);
    b.push(n as u8);
    for &(ip, port, id) in &list[..n] {
        b.extend_from_slice(&ip.to_be_bytes());
        b.extend_from_slice(&port.to_le_bytes());
        b.extend_from_slice(&id.to_le_bytes());
    }
    let c = crc32(&b);
    b.extend_from_slice(&c.to_le_bytes());
    b
}

/// A FAR datagram, part `part` of `parts`: (id, status, place, orientation as the SNAP carried it, name) each, at most
/// FAR_PART.
pub fn encode_far(sender: u32, seq: u16, part: u8, parts: u8, list: &[(u32, u8, [f32; 3], [i16; 4], &str)]) -> Vec<u8> {
    let n = list.len().min(FAR_PART);
    let mut b = Vec::with_capacity(HDR + 1 + 50 * n + CRC);
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&[1, MSG_FAR, 0, 0]);
    b.extend_from_slice(&sender.to_le_bytes());
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(&[part, parts]);
    b.push(n as u8);
    for &(id, status, p, q, name) in &list[..n] {
        b.extend_from_slice(&id.to_le_bytes());
        b.push(status);
        p.iter().for_each(|x| b.extend_from_slice(&x.to_le_bytes()));
        q.iter().for_each(|x| b.extend_from_slice(&x.to_le_bytes()));
        let nm = &name.as_bytes()[..name.len().min(24)];
        b.push(nm.len() as u8);
        b.extend_from_slice(nm);
    }
    let len = (b.len() + CRC) as u16;
    b[6..8].copy_from_slice(&len.to_le_bytes());
    let c = crc32(&b);
    b.extend_from_slice(&c.to_le_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_and_framing() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        let p = encode_peers(9, 1, &[(0x0A4D_0102, ROAM_PORT, 77)]);
        assert_eq!(&p[..4], MAGIC);
        assert_eq!(p[5], MSG_PEERS);
        assert_eq!(u16::from_le_bytes([p[6], p[7]]) as usize, p.len());
        assert_eq!(u32::from_le_bytes(p[p.len() - 4..].try_into().unwrap()), crc32(&p[..p.len() - 4]));
        // a hub-bound decoder takes its own lists as "not for me"
        assert_eq!(decode(&p), Some(Msg::Other));
        let f = encode_far(9, 2, 0, 1, &[(5, ST_ROAM, [1.0, 2.0, 3.0], [0; 4], "Ann")]);
        assert_eq!(u16::from_le_bytes([f[6], f[7]]) as usize, f.len());
        assert_eq!(decode(&f), Some(Msg::Other));
        assert_eq!(decode(&p[..p.len() - 1]), None, "length must match");
    }
}
