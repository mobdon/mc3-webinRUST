//! The Xbox kernel's crypto exports (ordinals 335-351), in place of xboxrecomp/src/kernel/kernel_crypto.c.
//!
//! Saves are signed with XcHMAC (HMAC-SHA1, src/web_fs.c sig_ok and the game's own writer), so every output
//! must stay byte-identical to the C: same null checks, same SHA-1 bit counter (two u32 words, the high one
//! counting carries), same RC4. The public-key, DES and service calls stay stubs (no Xbox Live).
//! `__stdcall` is empty on every host we build (xbox_winnt.h), so these are plain `extern "C"`.

use core::ffi::{c_char, c_int, c_void};

/// XBOX_SHA_CONTEXT (kernel.h): State[5], Count[2] (bits, low word first), Buffer[64]. 92 bytes.
#[repr(C)]
pub struct ShaContext {
    pub state: [u32; 5],
    pub count: [u32; 2],
    pub buffer: [u8; 64],
}

/// XBOX_RC4_CONTEXT (kernel.h): S[256], i, j. 258 bytes.
#[repr(C)]
pub struct Rc4Context {
    pub s: [u8; 256],
    pub i: u8,
    pub j: u8,
}

const _: () = assert!(size_of::<ShaContext>() == 92 && size_of::<Rc4Context>() == 258);

fn sha1_transform(state: &mut [u32; 5], block: &[u8]) {
    let mut w = [0u32; 80];
    for (i, c) in block[..64].chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..20 => ((b & c) | (!b & d), 0x5A827999),
            20..40 => (b ^ c ^ d, 0x6ED9EBA1),
            40..60 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
        *s = s.wrapping_add(v);
    }
}

pub fn sha_init(ctx: &mut ShaContext) {
    ctx.state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    ctx.count = [0, 0];
    ctx.buffer = [0; 64];
}

pub fn sha_update(ctx: &mut ShaContext, input: &[u8]) {
    if input.is_empty() {
        return;
    }
    // The C counts in u32 (ULONG InputLength): keep its wrap-around exactly.
    let len = input.len() as u32;
    let mut index = ((ctx.count[0] >> 3) & 0x3F) as usize;
    ctx.count[0] = ctx.count[0].wrapping_add(len << 3);
    if ctx.count[0] < (len << 3) {
        ctx.count[1] = ctx.count[1].wrapping_add(1);
    }
    ctx.count[1] = ctx.count[1].wrapping_add(len >> 29);

    let part = 64 - index;
    let mut i = 0;
    if input.len() >= part {
        ctx.buffer[index..].copy_from_slice(&input[..part]);
        sha1_transform(&mut ctx.state, &ctx.buffer);
        i = part;
        while i + 63 < input.len() {
            sha1_transform(&mut ctx.state, &input[i..i + 64]);
            i += 64;
        }
        index = 0;
    }
    ctx.buffer[index..index + input.len() - i].copy_from_slice(&input[i..]);
}

pub fn sha_final(ctx: &mut ShaContext) -> [u8; 20] {
    let mut bits = [0u8; 8];
    bits[..4].copy_from_slice(&ctx.count[1].to_be_bytes());
    bits[4..].copy_from_slice(&ctx.count[0].to_be_bytes());
    sha_update(ctx, &[0x80]);
    while (ctx.count[0] >> 3) % 64 != 56 {
        sha_update(ctx, &[0]);
    }
    sha_update(ctx, &bits);
    let mut out = [0u8; 20];
    for (o, s) in out.chunks_exact_mut(4).zip(ctx.state) {
        o.copy_from_slice(&s.to_be_bytes());
    }
    out
}

fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut ctx = ShaContext { state: [0; 5], count: [0; 2], buffer: [0; 64] };
    sha_init(&mut ctx);
    for p in parts {
        sha_update(&mut ctx, p);
    }
    sha_final(&mut ctx)
}

pub fn rc4_key(ctx: &mut Rc4Context, key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for (i, s) in ctx.s.iter_mut().enumerate() {
        *s = i as u8;
    }
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(ctx.s[i]).wrapping_add(key[i % key.len()]);
        ctx.s.swap(i, j as usize);
    }
    ctx.i = 0;
    ctx.j = 0;
}

pub fn rc4_crypt(ctx: &mut Rc4Context, data: &mut [u8]) {
    for b in data {
        ctx.i = ctx.i.wrapping_add(1);
        ctx.j = ctx.j.wrapping_add(ctx.s[ctx.i as usize]);
        ctx.s.swap(ctx.i as usize, ctx.j as usize);
        *b ^= ctx.s[ctx.s[ctx.i as usize].wrapping_add(ctx.s[ctx.j as usize]) as usize];
    }
}

/// HMAC-SHA1 of data1 || data2 (RFC 2104; the Xbox's XcHMAC takes two buffers).
pub fn hmac(key: &[u8], data1: &[u8], data2: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..20].copy_from_slice(&sha1(&[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad = k.map(|b| b ^ 0x36);
    let opad = k.map(|b| b ^ 0x5C);
    let inner = sha1(&[&ipad, data1, data2]);
    sha1(&[&opad, &inner])
}

// ---- The C ABI (kernel.h names, kernel_thunks.c's table) ----

/// A C (pointer, length) as a slice; a null pointer or zero length is empty, as the C skipped those.
unsafe fn bytes<'a>(p: *const u8, n: u32) -> &'a [u8] {
    if p.is_null() || n == 0 { &[] } else { unsafe { core::slice::from_raw_parts(p, n as usize) } }
}

#[cfg(not(test))]
fn warn(msg: &core::ffi::CStr) {
    unsafe extern "C" {
        fn xbox_log(level: c_int, subsystem: *const c_char, fmt: *const c_char, ...);
    }
    // XBOX_LOG_WARN, XBOX_LOG_CRYPTO (kernel.h); the message goes through "%s", never as a format.
    unsafe { xbox_log(1, c"CRYPTO".as_ptr(), c"%s".as_ptr(), msg.as_ptr()) }
}
#[cfg(test)]
fn warn(_: &core::ffi::CStr) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn xbox_XcSHAInit(ctx: *mut ShaContext) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        sha_init(ctx);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn xbox_XcSHAUpdate(ctx: *mut ShaContext, input: *const u8, len: u32) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        sha_update(ctx, unsafe { bytes(input, len) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn xbox_XcSHAFinal(ctx: *mut ShaContext, digest: *mut u8) {
    if let (Some(ctx), false) = (unsafe { ctx.as_mut() }, digest.is_null()) {
        let d = sha_final(ctx);
        unsafe { core::ptr::copy_nonoverlapping(d.as_ptr(), digest, 20) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn xbox_XcRC4Key(ctx: *mut Rc4Context, len: u32, key: *const u8) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        rc4_key(ctx, unsafe { bytes(key, len) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn xbox_XcRC4Crypt(ctx: *mut Rc4Context, len: u32, data: *mut u8) {
    if let (Some(ctx), false) = (unsafe { ctx.as_mut() }, data.is_null() || len == 0) {
        rc4_crypt(ctx, unsafe { core::slice::from_raw_parts_mut(data, len as usize) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn xbox_XcHMAC(
    key: *const u8, key_len: u32, d1: *const u8, d1_len: u32, d2: *const u8, d2_len: u32, digest: *mut u8,
) {
    if key.is_null() || digest.is_null() {
        return;
    }
    let h = unsafe { hmac(bytes(key, key_len), bytes(d1, d1_len), bytes(d2, d2_len)) };
    unsafe { core::ptr::copy_nonoverlapping(h.as_ptr(), digest, 20) };
}

// Public key, DES and service calls: stubs, as in the C (no Xbox Live, no EEPROM/HDD keys).

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcPKGetKeyLen(_: *mut c_void) -> u32 { 0 }

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcPKDecPrivate(_: *mut c_void, _: *mut c_void, _: *mut c_void) -> u32 {
    warn(c"XcPKDecPrivate: stubbed (no Xbox Live)");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcPKEncPublic(_: *mut c_void, _: *mut c_void, _: *mut c_void) -> u32 {
    warn(c"XcPKEncPublic: stubbed (no Xbox Live)");
    0
}

/// TRUE: signature checks pass (as the C).
#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcVerifyPKCS1Signature(_: *mut c_void, _: *mut c_void, _: *mut c_void) -> u8 { 1 }

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcModExp(_: *mut u32, _: *mut u32, _: *mut u32, _: *mut u32, _: u32) -> u32 {
    warn(c"XcModExp: stubbed");
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcDESKeyParity(_: *mut u8, _: u32) {}

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcKeyTable(_: u32, _: *mut c_void, _: *const u8) {}

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcBlockCrypt(_: u32, _: *mut c_void, _: *mut c_void, _: *mut c_void, _: u32) {}

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcBlockCryptCBC(
    _: u32, _: u32, _: *mut c_void, _: *mut c_void, _: *mut c_void, _: u32, _: *mut c_void,
) {
}

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcCryptService(_: u32, _: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn xbox_XcUpdateCrypto(_: *mut c_void, _: *mut c_void) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha1_fips_vectors() {
        assert_eq!(hex(&sha1(&[b"abc"])), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(&sha1(&[b""])), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        let m = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(hex(&sha1(&[m])), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
        let a = vec![b'a'; 1_000_000];
        assert_eq!(hex(&sha1(&[&a])), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        // Split anywhere: the same digest as one update.
        for cut in [1, 55, 56, 63, 64, 65, 127] {
            assert_eq!(sha1(&[&a[..cut], &a[cut..1000]]), sha1(&[&a[..1000]]));
        }
    }

    #[test]
    fn hmac_rfc2202() {
        assert_eq!(hex(&hmac(&[0x0b; 20], b"Hi There", b"")), "b617318655057264e28bc0b6fb378c8ef146be00");
        assert_eq!(hex(&hmac(b"Jefe", b"what do ya want ", b"for nothing?")), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        assert_eq!(
            hex(&hmac(&[0xaa; 80], b"Test Using Larger Than Block-Size Key - Hash Key First", b"")),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    #[test]
    fn rc4_vectors() {
        let mut c = Rc4Context { s: [0; 256], i: 0, j: 0 };
        rc4_key(&mut c, b"Key");
        let mut d = *b"Plaintext";
        rc4_crypt(&mut c, &mut d);
        assert_eq!(hex(&d), "bbf316e8d940af0ad3");
    }

    #[test]
    fn c_abi_null_and_empty() {
        let mut d = [7u8; 20];
        unsafe {
            xbox_XcHMAC(core::ptr::null(), 0, core::ptr::null(), 0, core::ptr::null(), 0, d.as_mut_ptr());
            assert_eq!(d, [7; 20]); // null key: untouched, as the C
            let z = [0u8; 16];
            xbox_XcHMAC(z.as_ptr(), 16, core::ptr::null(), 5, core::ptr::null(), 0, d.as_mut_ptr());
        }
        assert_eq!(d, hmac(&[0; 16], b"", b""));
    }
}
