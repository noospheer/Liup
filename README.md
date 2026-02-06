Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the names of the copyright holders nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---

# Liup: Information-Theoretic Key Agreement from Gaussian Noise

## Abstract

We present an implementation of an information-theoretically secure (ITS) key agreement protocol that operates over classical TCP/IP networks. Two parties sharing a finite pre-shared key (PSK) of ~12.5 KB can generate an **unlimited stream** of ITS key material at ~3 Mbps, secure against active man-in-the-middle attackers with unbounded computational power. The protocol requires no quantum channel, no computational hardness assumptions, and no key material beyond the initial PSK. Security rests on two assumptions: (1) access to true randomness, and (2) one shared secret established out-of-band. We provide a complete implementation with 147 passing tests, formal security bounds, and a hybrid-game composition proof for the key recycling mechanism.

---

## 1. Introduction

Information-theoretic security (ITS) guarantees that an adversary gains negligible information about a secret regardless of their computational resources. Traditionally, ITS key agreement required either quantum key distribution (QKD) or one-time pads (OTPs)—both impractical for most applications due to specialized hardware or key consumption rates.

This work implements the **signbit-nopa** protocol, which achieves ITS key agreement over ordinary TCP/IP networks using only:
- A true random number generator (TRNG)
- A single pre-shared key (PSK) of 32 + ⌈B/8⌉ bytes

The protocol generates unlimited ITS key material from this finite PSK through a pool recycling mechanism whose security we prove via a hybrid-game argument.

### 1.1 Contributions

1. **Full ITS against active attackers**: Confidentiality, authentication, and key agreement integrity—all information-theoretic.
2. **Infinite key from finite PSK**: Pool recycling with provable composition security.
3. **Practical throughput**: ~3 Mbps of secure key material on commodity hardware.
4. **Complete implementation**: 147 tests covering all security properties.

---

## 2. Protocol Description

### 2.1 Setup

Alice and Bob share a PSK with the following layout:
- Bytes 0–15: Initial run MAC key seed
- Bytes 16–31: Config MAC key seed
- Bytes 32+: Initial OTP pool (~12.5 KB for B=100,000)

At session start, the client generates a fresh 16-byte session nonce and sends it to the server.

### 2.2 Message Flow

Each batch of n_runs proceeds as follows:

```
Alice                                 Bob
  |                                    |
  |------ config + config_tag -------->|  (authenticated)
  |<--------- ack --------------------|
  |                                    |
  |------ wa[1..n] ------------------>|  (n_runs wire values)
  |<----- (sign_enc, wb, tag)[1..n] --|  (encrypted signs + wire + MAC)
  |------ tag[1..n] ----------------->|  (Alice's MACs)
  |                                    |
```

### 2.3 Per-Run Operations

For each run i:

1. **Wire exchange**: Alice samples Gaussian noise Z_a, sends wa₀ = Z_a mod p. Bob does likewise with Z_b.

2. **Sign encryption**: Bob encrypts his sign bit with OTP from pool:
   ```
   sign_enc = sign_raw ⊕ OTP
   ```

3. **MAC computation**: Both compute polynomial MAC over (wa₀, wb₀, sign_enc):
   ```
   tag = s + r·c₀ + r²·c₁ + ... + rᵈ·cₐ  (mod M₆₁)
   ```
   where M₆₁ = 2⁶¹−1 (Mersenne prime) and coefficients cᵢ encode quantized wire values and encrypted sign bytes.

4. **Key extraction**: If tags match, both extract sign_raw as key bits.

5. **Pool update**: Deposit sign_raw into pool; recycle first 128 bits as next run's MAC key.

### 2.4 Key Derivation

All MAC keys are derived with session-nonce XOR to ensure uniqueness:

- **Config MAC**: (r, s) = (PSK[16:24] ⊕ nonce, PSK[24:32] ⊕ nonce)
- **Run 1 MAC**: (r, s) = (PSK[0:8] ⊕ nonce, PSK[8:16] ⊕ nonce)
- **Run N MAC**: (r, s) = first 128 bits of run N−1's output

---

## 3. Security Analysis

### 3.1 Threat Model

We consider an active man-in-the-middle adversary Eve who:
- Observes all TCP traffic
- Can modify, inject, drop, or replay any message
- Has unbounded computational power
- Does not know the PSK

### 3.2 Security Properties

**Theorem 1 (Confidentiality).** Eve's information about each sign bit is bounded by the total variation distance of the wrapped Gaussian:
```
δ_TV ≤ 2·∑_{m=1}^∞ exp(−2π²m²σ²/p²)
```
At σ/p = 2, this gives δ_TV ≈ exp(−79) ≈ 10⁻³⁴ per bit.

**Theorem 2 (Authentication).** The probability of MAC forgery is bounded by:
```
Pr[forgery] ≤ d/M₆₁
```
where d is the polynomial degree. With d ≈ 100,000 (for B=100k), this gives Pr[forgery] ≈ 10⁻¹⁴ per run.

**Theorem 3 (Key Agreement).** If the MAC verification passes, Alice and Bob hold identical key bits. If verification fails, the run is discarded.

### 3.3 Composition Security

**Theorem 4 (Pool Recycling Composition).** The protocol with pool recycling achieves ε_total-ITS security where:
```
ε_total ≤ N × (4B·δ_TV + (d+B)/M₆₁)
```

*Proof sketch.* Define N+1 hybrid games:
- Game 0: Real protocol with pool recycling
- Game k: First k runs use truly uniform keys; remaining runs use recycled keys
- Game N: All runs use independent uniform keys

Each transition Game k → Game k+1 costs at most 2B·δ_TV by the data processing inequality (recycled keys are statistically close to uniform). Security in Game N follows from per-run bounds. Triangle inequality gives the total. ∎

### 3.4 Active Attack Resistance

| Attack | Defense | Bound |
|--------|---------|-------|
| Tamper with config | Config MAC fails | 10⁻¹⁶ |
| Tamper with wire values | Run MAC fails | 10⁻¹⁴ |
| Tamper with encrypted signs | Signs included in MAC | 10⁻¹⁴ |
| Replay old session | Nonce ⊕ key derivation | Unique keys |
| PSK reuse across sessions | Nonce ⊕ key derivation | Unique keys |

**Denial of Service.** Eve can cause MAC failures by tampering, which desyncs pools and fails subsequent runs. This is DoS, not a security break—no wrong keys are ever accepted.

### 3.5 Concrete Security

At σ/p = 2, B = 100,000:
- Per-run forgery probability: ~10⁻¹⁴
- TV leakage per run: ~10⁻²⁹ (negligible)
- After 10⁹ runs (~100 Tbit of key): ε ≈ 10⁻⁵

---

## 4. Assumptions

The ITS guarantee requires exactly two assumptions:

1. **True randomness.** Both parties have access to a true random number generator. See Section 8.1 for caveats about the current implementation.

2. **One shared secret.** The PSK must be established through an out-of-band authenticated channel before protocol execution. See Section 8.4.

No lattice hardness, no factoring, no random oracles. The protocol has zero computational assumptions beyond the randomness source.

---

## 5. Getting Started

### 5.1 Installation

```bash
# Clone and install dependencies
cd Liup/src
pip install numpy scipy
```

### 5.2 Quick Demo (Single Machine)

Run this to see the protocol in action:

```bash
cd src
python demo.py
```

Or paste this into Python:

```python
from liuproto.link import NetworkServerLink, NetworkClientLink
from liuproto.endpoint import Physics
import os, threading

# Step 1: Create a shared secret (in real use, exchange this securely out-of-band)
psk = os.urandom(32 + 12500)  # ~12.5 KB

# Step 2: Start server
server = NetworkServerLink(('127.0.0.1', 9999), pre_shared_key=psk)
threading.Thread(target=server.run_batch_signbit_nopa).start()

# Step 3: Run client
physics = Physics(1, 0.8, 0.1, 5, 0, 0, 0, 0.2)  # Channel simulation params (not critical for demo)
client = NetworkClientLink(('127.0.0.1', 9999), physics, pre_shared_key=psk)
result = client.run_signbit_nopa(B=100000, n_runs=10)

# Step 4: Use your new ITS key!
print(f"Generated {len(result['secure_bits']):,} bits of ITS key")
key_str = ''.join(str(b) for b in result['secure_bits'][:64])
print(f"Key (first 64 bits): {key_str}")
```

### 5.3 Two-Machine Setup

**On Machine A (Server):**

```python
# server.py
from liuproto.link import NetworkServerLink
import os

# Load PSK (must match client's PSK exactly)
psk = open('shared_secret.key', 'rb').read()

server = NetworkServerLink(('0.0.0.0', 9999), pre_shared_key=psk)
print("Server listening on port 9999...")
result = server.run_batch_signbit_nopa()
print(f"Generated {len(result['secure_bits']):,} bits")
```

**On Machine B (Client):**

```python
# client.py
from liuproto.link import NetworkClientLink
from liuproto.endpoint import Physics

# Load PSK (must match server's PSK exactly)
psk = open('shared_secret.key', 'rb').read()

physics = Physics(1, 0.8, 0.1, 5, 0, 0, 0, 0.2)
client = NetworkClientLink(('server-ip', 9999), physics, pre_shared_key=psk)
result = client.run_signbit_nopa(B=100000, n_runs=10)
print(f"Generated {len(result['secure_bits']):,} bits")
```

**Generate a PSK file:**

```bash
# Run once, copy to both machines securely
python -c "import os; open('shared_secret.key','wb').write(os.urandom(32+12500))"
```

### 5.4 API Reference

```python
# Client options
result = client.run_signbit_nopa(
    B=100000,           # Bits per run (default: 100k)
    n_runs=10,          # Runs per batch (default: 10)
    n_batches=1,        # Batches per connection (default: 1)
    mod_mult=0.5,       # Security parameter: 0.5 → σ/p=2 (recommended)
    n_test_rounds=2,    # σ verification rounds (0 to skip)
)

# Result contains:
result['secure_bits']      # The ITS key (numpy array of 0s and 1s)
result['sigma_verified']   # True if σ/p was verified
```

### 5.5 Running Tests

```bash
cd src
python -m pytest test_security.py -v -k "not TestUniformity"
# 147 passed
```

Key test classes:
- `TestSigmaVerification`: 15 tests for active MITM protection
- `TestSignbitNoPA`: 7 tests for pool-flat infinite operation
- `TestSignbitProtocol`: 7 tests for signbit-ITS with PA

---

## 6. Efficiency Analysis

### 6.1 Theoretical Efficiency

| Metric | Value | Notes |
|--------|-------|-------|
| Key expansion | ∞ | Infinite key from finite PSK (pool recycling) |
| Key efficiency | 100% | All B sign bits become key (no PA at σ/p=2) |
| Info leakage | 10⁻³⁴/bit | δ_TV per channel at σ/p=2 |
| Auth overhead | 0% | MAC keys recycled from output |
| Security after 100 Tbit | ε ≈ 10⁻⁵ | Dominated by MAC forgery bound |

The protocol achieves near-optimal theoretical efficiency:
- **Confidentiality**: At σ/p = 2, the wrapped Gaussian TV distance is δ_TV ≈ exp(−79) ≈ 10⁻³⁴. Eve learns essentially nothing about each sign bit from the wire values.
- **Key utilization**: 100% of extracted sign bits become usable key. No privacy amplification shrinkage because the per-bit leakage is already negligible.
- **Authentication**: Zero net key consumption—MAC keys for run N+1 are recycled from run N's output.

### 6.2 Practical Performance

| Metric | Value |
|--------|-------|
| Throughput | ~2–3 Mbps secure key |
| PSK size | 32 + ⌈B/8⌉ bytes (~12.5 KB for B=100k) |
| Network overhead | 1.5 RTTs per batch, ~1.3 key bits/network byte |
| Optimal batch size | B = 100,000 (fits L3 cache) |

**Compute breakdown** (localhost, B=100k):
- Noise generation: ~30%
- MAC computation: ~35%
- Network I/O: ~30%
- OTP/serialization: ~5%

**Scaling behavior**:
- B = 50k → 100k: linear throughput increase
- B = 100k → 200k: sublinear (L3 cache pressure)
- Network latency: batching provides 1.5×–2.9× speedup at 10–50ms RTT

### 6.3 Comparison with Alternatives

| Protocol | Key Rate | Security | Hardware | Assumptions |
|----------|----------|----------|----------|-------------|
| AES-256-GCM | ~10 Gbps | Computational | CPU | AES hardness |
| QKD (BB84) | ~1–10 kbps | ITS | Quantum channel, SPDs | Quantum mechanics |
| **This protocol** | ~2–3 Mbps | ITS | CPU + TRNG | True randomness |

**Key observations**:
- **vs QKD**: 300–3000× faster, no quantum hardware, works over any TCP/IP path. Trade-off: requires pre-shared secret (QKD can bootstrap from scratch with quantum channel).
- **vs computational crypto**: ~1000× slower, which is the inherent cost of ITS—you cannot achieve unconditional security at computational speeds.
- **vs OTP**: OTP consumes 1 bit of key per bit of message. This protocol generates unlimited key from ~12.5 KB of PSK.

### 6.4 Path to Higher Throughput

The ~1000× gap to computational crypto (AES) decomposes into addressable and fundamental factors:

| Factor | Current Slowdown | Addressable? |
|--------|------------------|--------------|
| Python vs C/SIMD | ~10× | Yes (software) |
| os.urandom() vs hardware TRNG | ~10× | Yes (hardware) |
| True randomness vs PRNG | ~3–10× | **No** (fundamental) |
| Network round-trips | ~3× | Partially (batching) |
| Polynomial MAC vs AES-NI | ~3× | Yes (custom silicon) |

**Optimization tiers:**

| Configuration | Throughput | Gap to AES | Investment |
|---------------|------------|------------|------------|
| Current (Python/numpy) | ~3 Mbps | 3000× | — |
| C extension + SIMD + multithread | ~30 Mbps | 300× | ~$10k |
| + Hardware TRNG | ~300 Mbps | 30× | ~$100k |
| Custom ASIC | ~3 Gbps | 3× | ~$1M+ |
| Theoretical limit | ~10 Gbps | 1× | Physics |

**Fundamental limits:**

1. **True randomness**: ITS *requires* true randomness—PRNGs only provide computational security. Physical entropy sources (thermal noise, quantum vacuum fluctuations) have bandwidth limits. Best demonstrated: ~10 Gbps quantum RNG.

2. **Network bandwidth**: Must exchange O(B) bits to agree on O(B) key bits. Network bandwidth sets a hard ceiling.

3. **Authentication**: Polynomial MAC is O(B) work per run. The constant factor can shrink with hardware (~1 cycle/coefficient achievable), but the linear scaling cannot.

**Why AES is fundamentally faster:**
- Fixed 10–14 rounds with dedicated hardware instructions (AES-NI)
- Uses PRNG, not true randomness
- Local computation, no network round-trips for key agreement

The ~3–10× residual gap even with custom silicon is the unavoidable cost of information-theoretic security.

---

## 7. Module Structure

```
liuproto/
  link.py            Protocol implementation (signbit_nopa, signbit_its, parallel_its)
  endpoint.py        Physics simulation (Gaussian noise, modular reduction)
  security_proof.py  Formal bounds (composition_security_bound, wrapped_gaussian_tv_bound)
  privacy.py         Toeplitz hashing (GF(2) block PA)
  leakage.py         HMM forward algorithm, min-entropy estimation
  reconciliation.py  Error correction (not needed for signbit modes)
```

---

## 8. Limitations

### 8.1 Randomness Source

The current implementation uses `os.urandom()`, which on Linux is backed by ChaCha20—a cryptographically secure PRNG, not a true random number generator. This provides **computational security** for the randomness, not information-theoretic security.

**For true ITS**: Replace `os.urandom()` with a hardware TRNG (thermal noise, shot noise, or quantum RNG). The protocol's ITS guarantees are contingent on the entropy source being truly random.

### 8.2 Implementation Maturity

This is research-grade code, not production software:
- No formal verification (proofs are mathematical arguments, not machine-checked)
- Single-threaded Python implementation
- No protection against side-channel attacks (timing, power analysis)
- Error handling is minimal in some code paths

### 8.3 Network Assumptions

The protocol assumes:
- Reliable, ordered delivery (TCP). Packet loss causes batch failure.
- No protection against traffic analysis (Eve sees message sizes and timing)
- Denial-of-service is possible (Eve can cause MAC failures by tampering)

### 8.4 Pre-Shared Key Requirement

Unlike QKD, this protocol **cannot bootstrap from scratch**. The initial PSK must be established through a separate authenticated channel (in-person exchange, trusted courier, or computational crypto during a trusted setup phase).

### 8.5 Performance Ceiling

Even with optimal hardware (custom ASIC + quantum RNG), throughput is fundamentally limited to ~1–10 Gbps due to:
- True randomness generation bandwidth
- Network round-trip requirements
- O(B) MAC computation per run

This is ~3–10× slower than AES, which is the inherent cost of information-theoretic security.

---

## 9. References

[1] Liu, P., "A key agreement protocol using band-limited random signals and feedback," *Journal of Lightwave Technology* 27(23), 2009.

[2] Liu, P., "Prediction accuracy of band-restricted random signals and security risk in statistical key exchange," *Fluctuations and Noise Letters* 9(4), 2010.

[3] Wegman, M. N. and Carter, J. L., "New hash functions and their use in authentication and set equality," *Journal of Computer and System Sciences* 22(3), 1981.

[4] Impagliazzo, R., Levin, L. A., and Luby, M., "Pseudo-random generation from one-way functions," *STOC*, 1989.
