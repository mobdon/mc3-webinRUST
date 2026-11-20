/*
 * test_rust_crypto.c - the Rust crypto (crates/client/mc3-runtime) against the C it replaces
 * (xboxrecomp/src/kernel/kernel_crypto.c), byte for byte, from several pthreads at once.
 * Proves the Rust staticlib links into an Emscripten -pthread build and gives the same saves' signatures.
 * Run: tools/test_rust_crypto.sh (native gcc, then Emscripten + Node).
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "kernel.h"   /* the xbox_Xc* names: the Rust staticlib */

/* The C side: kernel_crypto.c compiled with every xbox_Xc* renamed c_Xc* (test_rust_crypto.sh). */
VOID c_XcSHAInit(PXBOX_SHA_CONTEXT);
VOID c_XcSHAUpdate(PXBOX_SHA_CONTEXT, const UCHAR *, ULONG);
VOID c_XcSHAFinal(PXBOX_SHA_CONTEXT, UCHAR *);
VOID c_XcRC4Key(PXBOX_RC4_CONTEXT, ULONG, const UCHAR *);
VOID c_XcRC4Crypt(PXBOX_RC4_CONTEXT, ULONG, UCHAR *);
VOID c_XcHMAC(const UCHAR *, ULONG, const UCHAR *, ULONG, const UCHAR *, ULONG, UCHAR *);
ULONG c_XcPKGetKeyLen(PVOID);
BOOLEAN c_XcVerifyPKCS1Signature(PVOID, PVOID, PVOID);

void xbox_log(int level, const char *subsystem, const char *fmt, ...) { (void)level; (void)subsystem; (void)fmt; }
VOID SecureZeroMemory(PVOID p, SIZE_T n) { memset(p, 0, n); }   /* platform layer, for kernel_crypto.c */

#define NTHREADS 4
#define ROUNDS 400

static uint32_t rng(uint32_t *s) { *s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5; return *s; }

static void *run(void *arg)
{
    uint32_t seed = 0x9E3779B9u * (uint32_t)(uintptr_t)arg + 1;
    static uint8_t bufs[NTHREADS][3][5000];
    uint8_t (*b)[5000] = bufs[(uintptr_t)arg];
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t n[3];
        for (int k = 0; k < 3; k++) {
            n[k] = rng(&seed) % (r & 1 ? 200 : 5000);
            for (uint32_t i = 0; i < n[k]; i++) b[k][i] = (uint8_t)rng(&seed);
        }
        uint8_t hr[20], hc[20];
        /* HMAC: key of any length (> 64 hashes it), two data parts, a null one now and then. */
        const uint8_t *d2 = (r % 7) ? b[2] : NULL;
        xbox_XcHMAC(b[0], n[0] % 150, b[1], n[1], d2, n[2], hr);
        c_XcHMAC(b[0], n[0] % 150, b[1], n[1], d2, n[2], hc);
        if (memcmp(hr, hc, 20)) { printf("FAIL hmac round %d\n", r); return (void *)1; }

        /* SHA in uneven pieces. */
        XBOX_SHA_CONTEXT sr, sc;
        xbox_XcSHAInit(&sr); c_XcSHAInit(&sc);
        for (uint32_t off = 0; off < n[1];) {
            uint32_t step = 1 + rng(&seed) % 130;
            if (step > n[1] - off) step = n[1] - off;
            xbox_XcSHAUpdate(&sr, b[1] + off, step); c_XcSHAUpdate(&sc, b[1] + off, step);
            off += step;
        }
        xbox_XcSHAFinal(&sr, hr); c_XcSHAFinal(&sc, hc);
        if (memcmp(hr, hc, 20) || memcmp(&sr, &sc, sizeof sr)) { printf("FAIL sha round %d\n", r); return (void *)1; }

        /* RC4. */
        XBOX_RC4_CONTEXT kr, kc;
        uint32_t kl = 1 + n[0] % 64;
        xbox_XcRC4Key(&kr, kl, b[0]); c_XcRC4Key(&kc, kl, b[0]);
        static uint8_t er[NTHREADS][5000], ec[NTHREADS][5000];
        memcpy(er[(uintptr_t)arg], b[2], n[2]); memcpy(ec[(uintptr_t)arg], b[2], n[2]);
        xbox_XcRC4Crypt(&kr, n[2], er[(uintptr_t)arg]); c_XcRC4Crypt(&kc, n[2], ec[(uintptr_t)arg]);
        if (memcmp(er[(uintptr_t)arg], ec[(uintptr_t)arg], n[2]) || memcmp(&kr, &kc, sizeof kr)) {
            printf("FAIL rc4 round %d\n", r); return (void *)1;
        }
    }
    return NULL;
}

int main(void)
{
    if (xbox_XcVerifyPKCS1Signature(0, 0, 0) != c_XcVerifyPKCS1Signature(0, 0, 0) ||
        xbox_XcPKGetKeyLen(0) != c_XcPKGetKeyLen(0)) {
        printf("FAIL stubs\n");
        return 1;
    }
    pthread_t t[NTHREADS];
    for (uintptr_t i = 0; i < NTHREADS; i++) pthread_create(&t[i], NULL, run, (void *)i);
    int bad = 0;
    for (int i = 0; i < NTHREADS; i++) { void *r; pthread_join(t[i], &r); bad |= r != NULL; }
    printf(bad ? "FAIL\n" : "OK: Rust crypto == C crypto, %d threads x %d rounds\n", NTHREADS, ROUNDS);
    return bad;
}
