/*
 * _fastrand.c — Fast Box-Muller Gaussian generation using getrandom().
 * Same entropy source as Python's os.urandom (Linux urandom pool).
 *
 * Also provides RDSEED support for near-ITS randomness.
 *
 * Compile: gcc -O3 -march=x86-64 -mpopcnt -shared -fPIC -lm -o _fastrand.so _fastrand.c
 *
 * NOTE: Do NOT use -march=native — the resulting binary is not portable
 * and will SIGILL on CPUs lacking the compile host's instruction set.
 *
 * API:  int batch_gaussian(double *out, int total)
 *       Fills out[0..total-1] with IID N(0,1) samples.
 *       Returns 0 on success, -1 on error.
 *
 *       int has_rdseed(void)
 *       Returns 1 if CPU supports RDSEED, 0 otherwise.
 *
 *       int batch_rdseed(uint8_t *out, int n_bytes)
 *       Fills out[0..n_bytes-1] with raw RDSEED bytes.
 *       Returns 0 on success, -1 if RDSEED fails after retries.
 */

#define _GNU_SOURCE
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/random.h>
#ifdef __x86_64__
#include <cpuid.h>
#endif

static int fill_random(void *buf, size_t len)
{
    unsigned char *p = (unsigned char *)buf;
    while (len > 0) {
        ssize_t got = getrandom(p, len, 0);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += got;
        len -= (size_t)got;
    }
    return 0;
}

int batch_gaussian(double *out, int total)
{
    if (total <= 0)
        return 0;

    int n_pairs = (total + 1) / 2;
    size_t raw_bytes = (size_t)n_pairs * 16;

    uint64_t *raw = (uint64_t *)malloc(raw_bytes);
    if (!raw)
        return -1;

    if (fill_random(raw, raw_bytes) < 0) {
        free(raw);
        return -1;
    }

    static const double SCALE = 1.0 / 18446744073709551616.0;
    static const double TWO_PI = 6.283185307179586476925286766559;

    int full_pairs = total / 2;
    for (int i = 0; i < full_pairs; i++) {
        double u1 = (double)raw[2*i] * SCALE;
        double u2 = (double)raw[2*i + 1] * SCALE;
        if (u1 < 1e-300) u1 = 1e-300;

        double r = sqrt(-2.0 * log(u1));
        double theta = TWO_PI * u2;
        double s, c;
        sincos(theta, &s, &c);

        out[2*i]     = r * c;
        out[2*i + 1] = r * s;
    }

    if (total & 1) {
        double u1 = (double)raw[2*full_pairs] * SCALE;
        double u2 = (double)raw[2*full_pairs + 1] * SCALE;
        if (u1 < 1e-300) u1 = 1e-300;
        out[total - 1] = sqrt(-2.0 * log(u1)) * cos(TWO_PI * u2);
    }

    free(raw);
    return 0;
}

/* ---- RDSEED support ---- */

int has_rdseed(void)
{
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
        return 0;
    return (ebx >> 18) & 1;  /* EBX bit 18 = RDSEED */
#else
    return 0;
#endif
}

int batch_rdseed(uint8_t *out, int n_bytes)
{
#ifdef __x86_64__
    int pos = 0;
    while (pos < n_bytes) {
        uint64_t val;
        unsigned char ok;
        int retries = 1000;
        do {
            __asm__ volatile("rdseed %0; setc %1"
                             : "=r"(val), "=qm"(ok));
            if (ok)
                break;
        } while (--retries > 0);
        if (!ok)
            return -1;

        int remaining = n_bytes - pos;
        int chunk = remaining < 8 ? remaining : 8;
        memcpy(out + pos, &val, chunk);
        pos += chunk;
    }
    return 0;
#else
    (void)out;
    (void)n_bytes;
    return -1;
#endif
}

/* ---- Toeplitz extraction (GF(2) matrix-vector via AND + popcount) ---- */

/*
 * toeplitz_extract: 2:1 block-wise Toeplitz extraction over GF(2).
 *
 * Each 64-byte (512-bit) input block is multiplied by a 256x512
 * Toeplitz matrix defined by 96 bytes of seed, producing 32 bytes
 * (256 bits) of output.
 *
 * The Toeplitz matrix row i = seed bits [i, i+1, ..., i+511] (MSB-first).
 * Output bit i = popcount(input_block AND row_i) mod 2.
 *
 * Returns number of output bytes written (n_blocks * 32), or 0 on error.
 *
 * seed must be at least 96 bytes (= 64 + 256/8).  Row i reads
 * seed[byte_off .. byte_off+64] where byte_off = i/8 (max 31),
 * plus seed[byte_off+64] for the bit-shift carry, so the maximum
 * index accessed is 31 + 64 = 95.
 */
int toeplitz_extract(const uint8_t *raw_in, int n_bytes_in,
                     const uint8_t *seed, int seed_len,
                     uint8_t *out)
{
    if (seed_len < 96)
        return 0;

    int n_blocks = n_bytes_in / 64;
    if (n_blocks <= 0)
        return 0;

    /* Precompute 256 Toeplitz rows, each 64 bytes (512 bits).
     * Row i is the seed bit-shifted left by i positions. */
    uint8_t rows[256][64];

    for (int i = 0; i < 256; i++) {
        int byte_off = i / 8;
        int bit_off  = i % 8;

        if (bit_off == 0) {
            memcpy(rows[i], seed + byte_off, 64);
        } else {
            for (int j = 0; j < 64; j++) {
                rows[i][j] = (uint8_t)(
                    (seed[byte_off + j]     << bit_off) |
                    (seed[byte_off + j + 1] >> (8 - bit_off)));
            }
        }
    }

    /* Extract: for each 64-byte input block, produce 32 output bytes */
    memset(out, 0, (size_t)n_blocks * 32);

    for (int block = 0; block < n_blocks; block++) {
        const uint64_t *in_w  = (const uint64_t *)(raw_in + block * 64);
        uint8_t *out_block = out + block * 32;

        /* Process 8 output bits at a time to build each output byte */
        for (int byte_i = 0; byte_i < 32; byte_i++) {
            uint8_t byte_val = 0;

            for (int b = 0; b < 8; b++) {
                int row_idx = byte_i * 8 + b;
                const uint64_t *row_w = (const uint64_t *)rows[row_idx];

                int parity = 0;
                for (int k = 0; k < 8; k++)
                    parity += __builtin_popcountll(in_w[k] & row_w[k]);

                byte_val |= ((parity & 1) << (7 - b));
            }

            out_block[byte_i] = byte_val;
        }
    }

    return n_blocks * 32;
}
