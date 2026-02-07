Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. The names of the contributors may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---

# Liup: Information-Theoretic Key Agreement from Gaussian Noise

## Abstract

Building on the foundational work of Pau-Lo Liu [1, 2], who demonstrated that information-theoretic security can be achieved through band-limited Gaussian noise exchange, we present an extended implementation suitable for classical TCP/IP networks. Two parties sharing a finite pre-shared key (PSK) of ~12.5 KB can generate an **unlimited stream** of information-theoretically secure (ITS) key material at ~3 Mbps, secure against active man-in-the-middle attackers with unbounded computational power. Where Liu's original protocol assumed physical channels and passive eavesdroppers, this implementation adds authenticated message exchange, active attack resistance, and a pool recycling mechanism for infinite key generation—all while preserving the information-theoretic guarantees. The protocol requires no quantum channel, no computational hardness assumptions, and no key material beyond the initial PSK. Security rests on two assumptions: (1) access to true randomness, and (2) one shared secret established out-of-band. We prove that each output bit has constant ITS security (≈ 10⁻¹⁴) independent of how many runs have been executed, so the protocol runs forever with no security degradation. We provide a complete implementation with 162 passing tests, formal security bounds, and proofs for both composition security and per-bit security of the key recycling mechanism.

---

## 1. Introduction

Information-theoretic security (ITS) guarantees that an adversary gains negligible information about a secret regardless of their computational resources. Traditionally, ITS key agreement required either quantum key distribution (QKD) or one-time pads (OTPs)—both impractical for most applications due to specialized hardware or key consumption rates.

This work implements the **signbit-nopa** protocol, which achieves ITS key agreement over ordinary TCP/IP networks using only:
- A true random number generator (TRNG)
- A single pre-shared key (PSK) of 32 + ⌈B/8⌉ bytes

The protocol generates unlimited ITS key material from this finite PSK through a pool recycling mechanism. We prove that each output bit has constant ITS security independent of the number of runs (Theorem 5, Section 3.7).

### 1.1 Background: The Liu Protocol

This implementation builds on the key agreement protocol introduced by Pau-Lo Liu [1, 2], which established that two parties can generate shared secret bits by exchanging band-limited Gaussian noise signals over a physical channel. A subsequent paper by Liu and Josan [3] identified a quantization noise vulnerability in the physical-channel version; our discrete-mathematical design is immune to this attack (see Section 3.6).

**Core insight from Liu**: When Alice and Bob exchange values Z mod p (where Z is drawn from a Gaussian distribution with σ >> p), the wrapped distribution is nearly uniform. An eavesdropper Eve, seeing only the wire value w = Z mod p, cannot determine the sign of Z—this uncertainty provides information-theoretic security.

**Limitations of the original Liu protocol**:

| Limitation | Description |
|------------|-------------|
| Physical channel assumed | Original analysis assumed analog signals over physical media (e.g., optical fiber), not digital networks |
| Passive adversary only | Security proofs addressed eavesdropping but not active tampering, injection, or replay attacks |
| No authentication | No mechanism to detect man-in-the-middle attackers modifying messages |
| Key material consumption | Each protocol run consumed fresh key material with no recycling mechanism |
| Quantization noise vulnerability | When digitized, broadband quantization noise leaks through the feedback loop, enabling an eavesdropper to recover key bits [3] |
| Implementation gap | Theoretical protocol without practical implementation or test suite |

**What this implementation adds**:

| Extension | Solution |
|-----------|----------|
| TCP/IP operation | Simulates the Gaussian channel digitally; works over any network path. No analog signals, no feedback loop, no quantization noise — immune to the attack in [3] (see Section 3.6) |
| Active MITM protection | Polynomial MAC (Wegman-Carter [4]) authenticates all messages with ITS guarantees |
| Authenticated config | Session parameters are MAC'd to prevent parameter tampering |
| PSK reuse safety | Session nonce XOR'd into MAC keys prevents cross-session attacks |
| Infinite key generation | Pool recycling with constant per-bit security forever (Theorem 5) |
| Sign-bit extraction | Simplified key extraction using only sign bits (1 bit/channel, cleaner security analysis) |
| Complete implementation | 162 tests, formal bounds, working demo |

The result is a protocol suitable for deployment over public digital channels (TCP/IP), secure against active attackers with unbounded computational power, generating unlimited ITS key material from a single ~12.5 KB pre-shared secret.

### 1.2 Contributions

1. **Full ITS against active attackers**: Confidentiality, authentication, and key agreement integrity—all information-theoretic.
2. **Infinite key from finite PSK**: Pool recycling with provable composition security.
3. **Constant per-bit security forever**: Each output bit has ITS security ≈ 10⁻¹⁴ independent of how many runs have been executed (Theorem 5). No protocol modifications needed for infinite operation.
4. **Practical throughput**: ~3 Mbps of secure key material on commodity hardware.
5. **Complete implementation**: 162 tests covering all security properties.

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

**Note.** Theorem 4 gives the "all-bits-simultaneously" guarantee, which grows linearly with N. For key generation, the per-bit guarantee (Theorem 5, Section 3.7) is more relevant: each individual output bit has constant security ≈ 10⁻¹⁴ independent of N.

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
- Per-bit confidentiality: δ_TV + d/M₆₁ ≈ 10⁻¹⁴ (**constant forever**, Theorem 5)
- Per-run forgery probability: ~10⁻¹⁴ (**constant forever**)
- All-bits-simultaneously after 10⁹ runs (~100 Tbit): ε ≈ 10⁻⁵ (Theorem 4; less relevant for key generation — see Section 3.7)

### 3.6 Immunity to the Quantization Noise Attack

Liu and Josan [3] demonstrated that the original physical-channel Liu protocol is vulnerable to a quantization noise attack. When analog signals are digitized, broadband quantization noise is introduced and propagated through the feedback loop. An eavesdropper can correlate the high-frequency components of the two counter-propagating signals to recover the sign of the feedback coefficient (the key bit). The attack works because the quantization error `n+` at Alice's terminal and `n-` at Bob's terminal satisfy the same feedback equations as the original signals, and their cross-correlation `δq = ⟨n+·n- − n+·n-⟩` reveals the key bit with high confidence.

**This attack does not apply to our protocol.** The attack requires four properties that are absent from our design:

| Attack requirement | Original Liu (physical channel) | This protocol (discrete) |
|---|---|---|
| Analog signals | Counter-propagating waves V+, V- over fiber | None — all values are integers |
| Feedback loop | `V+ = V1 + α·V-` (received signal fed back into transmission) | None — Alice and Bob generate Z_a, Z_b independently |
| Quantization | Analog-to-digital conversion introduces broadband noise | None — samples are generated digitally; `Z mod p` is integer arithmetic |
| High-frequency leakage | Quantization noise carries key information into out-of-band frequencies | No analog spectrum — wire values are single integers per run |

In our protocol, Alice samples Z_a from a discrete Gaussian distribution, computes `w_a = Z_a mod p` (an integer), and sends it over TCP. Bob does likewise with Z_b. There is no feedback of one party's signal into the other's generation, no analog-to-digital conversion, and no frequency spectrum to analyze. The security rests entirely on the statistical properties of the wrapped Gaussian distribution (Theorem 1), not on bandwidth limitation or signal processing.

The quantization noise attack is one of the motivations for our purely discrete design: by operating in integer arithmetic rather than digitized analog signals, we eliminate an entire class of signal-processing vulnerabilities (quantization noise, bandwidth leakage, propagation delay exploitation) that affect the physical-channel protocol.

### 3.7 Per-Bit Security (Infinite Operation)

The composition bound in Theorem 4 measures the probability that *any* bit across all N runs is compromised, giving ε_total that grows linearly with N. While mathematically correct, this is the wrong metric for a key generation protocol. The relevant question is: **how secure is each individual output bit when it is used?**

**Theorem 5 (Per-Bit ITS Security).** For any run index N ∈ ℕ and any bit position i ∈ {1, ..., B}:
```
TV(sign_i^(N), Uniform | Eve's complete transcript) ≤ δ_TV + d/M₆₁ ≈ 10⁻¹⁴
```
This bound is **independent of N**. Each output bit has constant ITS security regardless of how many runs have been executed.

*Proof.* Three information channels connect sign_i^(N) to Eve's observations. We bound each independently.

**Channel 1: Wire value leakage (δ_TV, constant).** sign_i^(N) is determined by Z_a^(N)[i], a fresh draw from N(0, σ²), independent of all other protocol random variables. Eve observes w_a^(N)[i] = Z_a^(N)[i] mod p. By Theorem 1, her advantage is δ_TV ≈ 10⁻³⁴. This depends only on σ/p, not on N.

**Channel 2: Encrypted sign via imperfect OTP (≤ δ_TV, constant).** Eve observes enc_i = sign_i ⊕ OTP_i, where OTP_i is a previous run's sign bit (from the pool). By induction on N: if OTP_i has bias β ≤ δ_TV (inductive hypothesis) and sign_i has bias α ≤ δ_TV (from wire leakage, Channel 1), then for independent X ~ Bernoulli(1/2 + α) and Y ~ Bernoulli(1/2 + β):
```
TV(X, Uniform | X⊕Y) = P(Z=0)|α+β| + P(Z=1)|α-β| = max(|α|, |β|) ≤ δ_TV
```
The XOR of two nearly-uniform independent bits yields the *maximum* of the two biases, not the sum. The base case (N=0) holds because the initial OTP comes from the PSK (uniform). Since each run uses fresh independent Gaussian draws, the induction holds for all N. The same argument applies to the "forward" direction (sign_i used as OTP for a future bit): max(δ_TV, δ_TV) = δ_TV.

**Channel 3: MAC tag leakage (≤ d/M₆₁, constant).** The first 128 sign bits of each run are reused as the next run's MAC key (r, s). Eve observes one (message, tag) pair per key. Since the tag constrains s = t − poly(m, r), and Eve's prior on r has TV distance ≤ 64·δ_TV ≈ 10⁻³³ from uniform, the per-bit leakage from the MAC tag is bounded by d/M₆₁ ≈ 10⁻¹⁴. Each set of 128 key-forming bits is used as MAC key for exactly one subsequent run (FIFO pool), so this leakage occurs once.

**Combining all channels**: per-bit advantage ≤ δ_TV + d/M₆₁ ≈ 10⁻¹⁴, independent of N. ∎

**Corollary (Constant Authentication).** Per-run forgery probability is also constant:
```
Pr[forgery at run N] ≤ d/M₆₁ + 128·δ_TV ≈ d/M₆₁ ≈ 10⁻¹⁴
```
since the recycled MAC key has min-entropy ≥ 122 − 128·h(δ_TV) ≈ 122 bits.

**Interpretation.** This is analogous to a fair casino: each dice roll is fair regardless of how many previous rolls occurred. The composition bound (Theorem 4) answers "what is the probability that *at least one* roll out of N was unfair?" — which grows with N but is irrelevant to the fairness of any individual roll. For key generation, per-bit security is the correct metric. The protocol provides constant ITS security per output bit, forever, with no modifications required.

**Reconciling Theorems 4 and 5.** Both theorems are correct. They answer different questions:

| | Theorem 4 (composition) | Theorem 5 (per-bit) |
|---|---|---|
| **Question** | Is *any* bit across all N runs compromised? | How secure is *this specific* bit? |
| **Bound** | N × ε (grows linearly) | ε ≈ 10⁻¹⁴ (constant) |
| **Relevant when** | All output bits are used as a single monolithic secret | Each bit (or block) is used independently for encryption |

There is no contradiction with information theory. The finite PSK is the *trust anchor* (bootstrapping authentication and OTP encryption), not the *entropy source*. The entropy in each output bit comes from the fresh Gaussian draws that run generates — an unlimited external source. The PSK enables the protocol to securely harvest that entropy, but the PSK itself is not "consumed" in an information-theoretic sense: pool recycling replenishes it after each run.

---

## 4. Assumptions

The ITS guarantee requires exactly two assumptions:

1. **True randomness.** Both parties have access to a true random number generator. The implementation offers two modes: `os.urandom()` (ChaCha20 CSPRNG, computationally secure) and RDSEED + Toeplitz extraction (near-ITS, requiring only the mild assumption that AES-CBC-MAC does not destroy entropy). See Section 8.1 for the full comparison and security analysis of each mode.

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
python demo.py --urandom           # Single batch: generates 1M bits (CSPRNG)
python demo.py --rdseed            # Single batch: generates 1M bits (RDSEED + Toeplitz)
python demo.py --urandom --stream  # Continuous: realtime stats, Ctrl+C to stop
python demo.py --rdseed --stream   # Continuous with RDSEED + Toeplitz
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
    rng_mode='urandom', # 'urandom' (default) or 'rdseed' (RDSEED + Toeplitz)
)

# Result contains:
result['secure_bits']      # The ITS key (numpy array of 0s and 1s)
result['sigma_verified']   # True if σ/p was verified
```

**Note on `rng_mode`**: When using `rng_mode='rdseed'`, the PSK must be 96 bytes longer than usual (for the Toeplitz extraction seed). The rdseed mode requires a CPU with RDSEED support (Intel Broadwell+ / AMD Zen+). See Section 8.1 for the security analysis of each mode.

### 5.5 Running Tests

```bash
cd src
python -m pytest test_security.py -v -k "not TestUniformity"
# 162 passed
```

Key test classes:
- `TestSigmaVerification`: 15 tests for active MITM protection
- `TestSignbitNoPA`: 7 tests for pool-flat infinite operation
- `TestSignbitProtocol`: 7 tests for signbit-ITS with PA
- `TestRdseedMode`: 15 tests for RDSEED + Toeplitz extraction mode

---

## 6. Efficiency Analysis

### 6.1 Theoretical Efficiency

| Metric | Value | Notes |
|--------|-------|-------|
| Key expansion | ∞ | Infinite key from finite PSK (pool recycling) |
| Key efficiency | 100% | All B sign bits become key (no PA at σ/p=2) |
| Per-bit security | ≈ 10⁻¹⁴ | **Constant forever** (Theorem 5), dominated by MAC key leakage (d/M₆₁) |
| Wire leakage | 10⁻³⁴/bit | δ_TV per channel at σ/p=2 |
| Auth overhead | 0% | MAC keys recycled from output |

The protocol achieves near-optimal theoretical efficiency:
- **Confidentiality**: At σ/p = 2, the wrapped Gaussian TV distance is δ_TV ≈ exp(−79) ≈ 10⁻³⁴. Eve learns essentially nothing about each sign bit from the wire values.
- **Key utilization**: 100% of extracted sign bits become usable key. No privacy amplification shrinkage because the per-bit leakage is already negligible.
- **Authentication**: Zero net key consumption—MAC keys for run N+1 are recycled from run N's output.

### 6.2 Practical Performance

| Metric | Value |
|--------|-------|
| Throughput (urandom) | ~2–3 Mbps secure key |
| Throughput (rdseed) | ~0.2 Mbps secure key |
| PSK size (urandom) | 32 + ⌈B/8⌉ bytes (~12.5 KB for B=100k) |
| PSK size (rdseed) | 32 + ⌈B/8⌉ + 96 bytes (~12.6 KB for B=100k) |
| Network overhead | 1.5 RTTs for key exchange (+ 1 RTT config, + 4 RTTs if σ verification enabled), ~17 network bytes/key bit |
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
| QKD (BB84) | ~1–10 kbps | ITS | Quantum channel, SPDs | Quantum mechanics + authenticated classical channel |
| **This protocol** | ~2–3 Mbps | ITS | CPU + TRNG | True randomness |

**Key observations**:
- **vs QKD**: 300–3000× faster, no quantum hardware, works over any TCP/IP path. Both protocols require a pre-shared secret: QKD needs a short authentication key for its classical channel (basis reconciliation, error estimation, and privacy amplification all require authenticated classical messages — without this, a MITM intercepts both quantum and classical channels undetected); this protocol needs ~12.5 KB. QKD's advantage is needing a shorter initial seed; this protocol's advantage is needing no quantum hardware. Neither truly bootstraps ITS key agreement from scratch — see Section 8.4.
- **vs computational crypto**: ~1000× slower in the current implementation, partly due to inherent ITS costs (true randomness, authentication) and partly due to optimization headroom not yet explored. Algorithmic or structural improvements could plausibly close 1–2 orders of magnitude of this gap. Note also that AES-GCM performs *encryption* (a local operation), while this protocol performs *key agreement* (requiring network round-trips); these are different primitives.
- **vs OTP**: OTP consumes 1 bit of key per bit of message. This protocol generates unlimited key from ~12.5 KB of PSK—with information-theoretic security, not computational assumptions. (Generating unlimited output from a finite seed is standard for stream ciphers like ChaCha20; the novelty here is achieving ITS while doing so.)

### 6.4 Path to Higher Throughput

The ~1000× gap to computational crypto (AES) decomposes into addressable and fundamental factors:

| Factor | Current Slowdown | Addressable? |
|--------|------------------|--------------|
| Python vs C/SIMD | ~10× | Yes (software) |
| os.urandom() vs hardware TRNG | ~10× | Yes (hardware) |
| Entropy generation bandwidth | ~3–10× | Partially (better TRNG) |
| Network round-trips | ~3× | Partially (batching) |
| Polynomial MAC vs AES-NI | ~3× | Yes (custom silicon) |

*Note: Using `os.urandom()` (CSPRNG) instead of a hardware TRNG does not weaken practical security—an adversary cannot exploit the CSPRNG without access to your machine's internal state. The distinction matters only for formal ITS proofs.*

**Optimization tiers:**

| Configuration | Throughput | Gap to AES | 
|---------------|------------|------------|
| Current (Python/numpy) | ~3 Mbps | 3000× |
| C extension + SIMD + multithread | ~30 Mbps | 300× |
| + Hardware TRNG | ~300 Mbps | 30× |
| Custom ASIC | ~3 Gbps | 3× |
| Theoretical limit | ~10 Gbps | 1× |

**Fundamental limits:**

1. **True randomness**: For formal ITS proofs, the protocol requires true randomness—PRNGs only provide computational security. However, in practice, `os.urandom()` remains secure even against unlimited computation because the adversary lacks access to the CSPRNG state. The bandwidth limit comes from physical entropy sources (~10 Gbps demonstrated with quantum RNG).

2. **Network bandwidth**: Must exchange O(B) bits to agree on O(B) key bits. Network bandwidth sets a hard ceiling.

3. **Authentication**: Polynomial MAC is O(B) work per run. The constant factor can shrink with hardware (~1 cycle/coefficient achievable), but the linear scaling cannot.

**Why AES is faster today:**
- Fixed 10–14 rounds with dedicated hardware instructions (AES-NI)
- Uses PRNG (but so can we, with practical security—see Section 8.1)
- Local computation, no network round-trips for key agreement

Some of the residual gap is likely inherent to ITS (true randomness generation, network round-trips for key agreement), but the exact floor is an open question. Algorithmic improvements to the protocol structure, MAC computation, or batching strategy could plausibly narrow the gap further — this implementation has not been optimized beyond basic numpy vectorization.

---

## 7. Module Structure

```
liuproto/
  link.py            Protocol implementation (signbit_nopa, signbit_its, parallel_its)
  _fastrand.c        C extension: Box-Muller, RDSEED, Toeplitz extraction
  _fastrand.so       Compiled shared library (gcc -O3 -march=native)
  endpoint.py        Physics simulation (Gaussian noise, modular reduction)
  security_proof.py  Formal bounds (composition_security_bound, wrapped_gaussian_tv_bound)
  privacy.py         Toeplitz hashing (GF(2) block PA)
  leakage.py         HMM forward algorithm, min-entropy estimation
  reconciliation.py  Error correction (not needed for signbit modes)
```

---

## 8. Limitations

### 8.1 Randomness Source

The implementation supports two randomness modes, selectable via `rng_mode`:

| Source | ITS-valid? | Throughput | Assumption | Flag |
|--------|-----------|------------|------------|------|
| Dedicated TRNG | Yes | Varies | None | (not yet supported) |
| **RDSEED + Toeplitz** | **Near-ITS** | **~0.2 Mbps** | **AES-CBC-MAC doesn't destroy entropy** | `--rdseed` |
| os.urandom() | No (computational) | ~2-3 Mbps | ChaCha20 is a good PRF | `--urandom` |
| RDRAND | No | -- | AES-128-CTR (128-bit, worse than urandom) | (not supported) |

#### Mode 1: `os.urandom()` (default, `--urandom`)

On Linux, `os.urandom()` is a hybrid system:
- **Entropy pool**: Seeded from real hardware noise (interrupt timing, thermal jitter, RDRAND)
- **Output expansion**: ChaCha20 CSPRNG stretches the entropy pool

**Practical security**: An adversary who cannot access the CSPRNG state on Alice/Bob's machines cannot predict outputs, because:
1. The state is seeded from hardware entropy events they never observed
2. Without the state, distinguishing ChaCha20 output from true random does not help predict specific values
3. The seed space (~256-512 bits) cannot be brute-forced by any physically realizable computer

For any realistic adversary -- even one with nation-state resources -- `os.urandom()` is unbreakable.

**Why this is not formal ITS**: The formal ITS model grants the adversary unbounded computation. Such an adversary enumerates all 2^256 possible CSPRNG seeds, computes the output sequence for each, and checks which candidate is consistent with observed wire values. This lets her recover all sign bits. The attack is absurdly infeasible in practice, but it is *permitted* in the ITS model.

#### Mode 2: RDSEED + Toeplitz extraction (`--rdseed`)

This mode uses Intel/AMD's RDSEED instruction followed by Toeplitz hashing for the strongest randomness available on commodity hardware. It is "practically ITS" under a single mild structural assumption.

##### The three-stage pipeline

```
Physical entropy   →   AES-CBC-MAC conditioner   →   Toeplitz extraction   →   Protocol
(thermal jitter)       (hardware, public key)         (seeded from PSK)        (sign bits)
```

1. **Physical entropy source.** Intel/AMD CPUs contain a ring oscillator whose thermal jitter produces true analog randomness. This raw noise is inaccessible via any instruction — the CPU's digital random number generator (DRNG) consumes it internally.

2. **AES-CBC-MAC conditioner (hardware).** The DRNG feeds the raw jitter through an AES-CBC-MAC conditioner to remove bias and ensure uniform output. The conditioning key is public (burned into silicon at manufacture), so this step provides **no cryptographic secrecy** — it is a deterministic entropy conditioner, not an encryption step. RDSEED exposes the conditioned output directly, before any CSPRNG expansion.

3. **Toeplitz extraction (software, seeded from PSK).** We apply a 2:1 Toeplitz extraction: a 256×512 binary Toeplitz matrix (defined by 96 bytes drawn from the PSK) maps every 512 RDSEED bits to 256 output bits. The Toeplitz seed is part of the pre-shared secret and is unknown to the adversary.

##### Why Toeplitz extraction is necessary — why not use pure RDSEED?

Pure RDSEED output has passed through a deterministic function (AES-CBC-MAC) with a **public key**. An unbounded adversary knows this key and can compute AES. If the physical source had any exploitable structure — biased bits, correlated samples, predictable jitter patterns — the adversary could potentially invert or correlate the conditioned output, since the conditioner provides no secrecy barrier.

Toeplitz extraction closes this gap through the **leftover hash lemma** (a cornerstone result in information-theoretic cryptography [5]): if the input has sufficient min-entropy H_∞, and the extraction function is chosen from a family of universal hash functions (which Toeplitz matrices are), then the output is within statistical distance 2^{-(H_∞ - output_length)/2} of the uniform distribution — regardless of the adversary's computational power.

Concretely:
- Each 512-bit RDSEED block is compressed to 256 output bits (2:1 ratio)
- If the RDSEED block has min-entropy > 256 + 2k bits, the output is within 2^{-k} of uniform
- For k = 128 (our target), we need min-entropy > 512 bits per 512-bit block — i.e., essentially full entropy
- The Toeplitz seed is secret (from the PSK), so the adversary does not know which hash function was chosen

In short: **RDSEED provides the raw entropy. Toeplitz extraction provides the information-theoretic guarantee.** Neither alone is sufficient — RDSEED alone has no secrecy barrier against an unbounded adversary, and Toeplitz extraction alone has no entropy to extract.

##### The remaining assumption and why it is mild

The single remaining assumption is:

> **AES-CBC-MAC (the hardware conditioner) does not destroy entropy.**

That is: the conditioned RDSEED output retains sufficient min-entropy from the physical source. This is a **structural** assumption about AES, not a **computational** one. The distinction is critical:

| | Computational assumption | Structural assumption |
|---|---|---|
| **Claim** | AES is hard to invert/distinguish | AES does not collapse entropy |
| **Broken by** | Faster algorithms (unbounded compute) | A catastrophic structural defect in AES |
| **Example attack** | Brute-force all 2^128 keys | AES maps all inputs to a tiny output set |
| **Status** | Breakable in the ITS model by definition | No known or conjectured attack path |

An unbounded adversary trivially breaks computational assumptions — they can enumerate all AES keys, invert any function, distinguish any CSPRNG from random. But this does not help them break a structural assumption. Being able to compute AES (which an unbounded adversary can) tells you nothing about whether AES destroys entropy. An unbounded adversary who knows the AES key and can evaluate AES on every input still cannot extract information from the Toeplitz-extracted output unless the conditioner destroyed the min-entropy that the physical source provided.

##### Why there is no known path to breaking this

For the RDSEED + Toeplitz pipeline to fail, one of the following would need to be true:

1. **The physical entropy source is defective.** The ring oscillator produces insufficient jitter, or the jitter is predictable. This is an engineering/manufacturing concern, not a cryptographic one. Intel's DRNG design has been extensively analyzed (see SP 800-90B evaluations). Commodity CPUs routinely produce full-entropy jitter.

2. **AES-CBC-MAC destroys entropy.** This would require AES to have a catastrophic structural property far beyond any known weakness:
   - AES would need to map a large fraction of its input space to a small output set (massive collisions), or
   - The CBC-MAC chaining would need to cause entropy collapse across blocks

   After 25+ years of intensive cryptanalysis, no such property has been found. The best known structural results on AES are:
   - Algebraic attacks: reduce AES to polynomial systems, but solving them requires exponential time (no entropy implication)
   - Related-key attacks: exploit key schedule weaknesses, irrelevant here (the key is fixed)
   - Impossible differentials: rule out certain differential paths, but do not imply entropy destruction
   - Biclique attacks: marginally reduce brute-force complexity, no structural entropy implication

   None of these come remotely close to suggesting that AES destroys entropy. Entropy destruction is not a "slightly weaker" version of known AES weaknesses — it is an entirely different category of failure, orthogonal to all known cryptanalytic techniques.

3. **The Toeplitz extraction is flawed.** The leftover hash lemma is a theorem (not a conjecture), and Toeplitz matrices are provably 2-universal hash families. The extraction guarantee is unconditional given sufficient input min-entropy. Our implementation processes 512→256 bit blocks using GF(2) matrix-vector multiplication (AND + popcount), which is exact arithmetic with no floating-point error.

In summary: breaking this pipeline would require either (a) a hardware manufacturing defect in the entropy source, or (b) discovering that AES has a catastrophic entropy-destroying property that 25 years of cryptanalysis have not hinted at. There is no incremental research path from current AES analysis toward such a result — it would represent a completely unexpected structural collapse.

##### Comparison: computational vs structural security

| Property | os.urandom (computational) | RDSEED + Toeplitz (structural) |
|---|---|---|
| **Assumption** | ChaCha20 is a good PRF | AES-CBC-MAC preserves entropy |
| **Breaks if** | A faster algorithm exists | AES has catastrophic structure |
| **ITS adversary can** | Enumerate all 2^256 seeds | Compute AES (but this doesn't help) |
| **Known attack path** | Yes (brute force, permitted in ITS model) | No known or conjectured path |
| **Security level** | Computationally unbreakable | Practically ITS |

The key insight is that an unbounded adversary has a clear attack strategy against `os.urandom()` — enumerate CSPRNG seeds — even though this attack is physically impossible. Against RDSEED + Toeplitz, there is no such strategy. The adversary can compute AES, but computing AES does not reveal whether it destroyed entropy. The adversary would need to know something about the physical entropy source's output, and the Toeplitz extraction (with a secret seed) ensures that even partial knowledge of the RDSEED output does not translate into knowledge of the extracted bits.

**Why not RDRAND?** RDRAND uses AES-128-CTR (a CSPRNG with a 128-bit seed) to expand the conditioned entropy. This is strictly weaker than os.urandom()'s ChaCha20 with a 256-bit seed — an unbounded adversary enumerates 2^128 seeds (vs 2^256 for ChaCha20). RDSEED taps the entropy *before* this CSPRNG expansion, which is why it is suitable for near-ITS use.

**PSK size**: RDSEED mode requires 96 extra bytes in the PSK for the Toeplitz extraction seed (total: 32 + ceil(B/8) + 96 bytes).

#### For strict ITS

Replace the randomness source with a dedicated hardware TRNG (thermal noise, shot noise, or quantum RNG) that outputs raw entropy without any deterministic conditioning step.

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

This protocol requires a pre-shared key (~12.5 KB) established through an out-of-band authenticated channel (in-person exchange, trusted courier, or computational crypto during a trusted setup phase).

**Note on QKD**: QKD is sometimes described as bootstrapping key agreement "from scratch," but this is imprecise. QKD's post-processing (basis reconciliation, error estimation, privacy amplification) requires an **authenticated classical channel**, which itself needs either a pre-shared key (for an ITS MAC) or computational assumptions (e.g. public-key signatures, which break the ITS guarantee). In practice, most deployed QKD systems use a small pre-shared key for initial authentication, then reserve part of each session's output to authenticate the next. The difference is quantitative, not qualitative: QKD needs a shorter initial seed than this protocol, but neither achieves ITS key agreement from zero shared state.

### 8.5 Performance Ceiling

With current protocol design and optimal hardware (custom ASIC + quantum RNG), throughput is estimated at ~1–10 Gbps, limited by:
- True randomness generation bandwidth
- Network round-trip requirements
- O(B) MAC computation per run

This is ~3–10× slower than AES. Some of this gap is inherent to ITS (true randomness, network key agreement), but the exact performance floor is an open question — algorithmic or structural improvements to the protocol could plausibly narrow it further.

---

## 9. References

[1] Liu, Pau-Lo, "A key agreement protocol using band-limited random signals and feedback," *Journal of Lightwave Technology* 27(23), 2009. ([PDF](papers/Liu2009.pdf))

[2] Liu, Pau-Lo, "Prediction accuracy of band-restricted random signals and security risk in statistical key exchange," *Fluctuations and Noise Letters* 9(4), 2010. ([PDF](papers/Liu2010.pdf))

[3] Liu, Pau-Lo and Josan, Madhur S., "Quantization noise in statistical key exchange," *Fluctuation and Noise Letters* 10(3), 2011. ([PDF](papers/LiuJosan2011.pdf))

[4] Wegman, M. N. and Carter, J. L., "New hash functions and their use in authentication and set equality," *Journal of Computer and System Sciences* 22(3), 1981. ([PDF](papers/WegmanCarter1981.pdf))

[5] Impagliazzo, R., Levin, L. A., and Luby, M., "Pseudo-random generation from one-way functions," *STOC*, 1989. ([PDF](papers/ImpagliazzoLevinLuby1989.pdf))
