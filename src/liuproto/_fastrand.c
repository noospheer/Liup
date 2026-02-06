/*
 * _fastrand.c — Fast Box-Muller Gaussian generation using getrandom().
 * Same entropy source as Python's os.urandom (Linux urandom pool).
 *
 * Compile: gcc -O3 -march=native -ffast-math -shared -fPIC -lm -o _fastrand.so _fastrand.c
 *
 * API:  int batch_gaussian(double *out, int total)
 *       Fills out[0..total-1] with IID N(0,1) samples.
 *       Returns 0 on success, -1 on error.
 */

#define _GNU_SOURCE
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/random.h>

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
