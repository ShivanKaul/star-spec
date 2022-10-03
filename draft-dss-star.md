---
title: "STAR: Distributed Secret Sharing for Private Threshold Aggregation Reporting"
abbrev: "STAR"
category: std
stream: IETF

docname: draft-dss-star-latest
ipr: trust200902
area: SEC

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    name: "Alex Davidson"
    organization: Brave Software
    email: "alex.davidson92@gmail.com"
 -
    name: "Shivan Kaul Sahib"
    organization: Brave Software
    email: "shivankaulsahib@gmail.com"
 -
    name: "Peter Snyder"
    organization: Brave Software
    email: "pes@brave.com"

normative:

  GCM: DOI.10.6028/NIST.SP.800-38D

informative:
  STAR:
    title: "STAR: Distributed Secret Sharing for Private Threshold Aggregation Reporting"
    date: 2022-04-10
    target: "https://arxiv.org/abs/2109.10074"
    author:
      - ins: A. Davidson
      - ins: P. Snyder
      - ins: E. Quirk
      - ins: J. Genereux
      - ins: H. Haddadi
      - ins: B. Livshits
  Tor:
    title: "Tor: The Second-Generation Onion Router"
    date: 2004
    target: "https://svn-archive.torproject.org/svn/projects/design-paper/tor-design.pdf"
    author:
      - ins: R. Dingledine
      - ins: N. Mathewson
      - ins: P. Syverson
  PrivateRelay:
    title: "iCloud Private Relay Overview"
    date: 2021
    target: https://www.apple.com/icloud/docs/iCloud_Private_Relay_Overview_Dec2021.pdf

  Brave:
    title: Brave Browser
    target: https://brave.com

  ADSS:
    title: "Reimagining Secret Sharing: Creating a Safer and More Versatile Primitive by Adding Authenticity, Correcting Errors, and Reducing Randomness Requirements"
    date: 2020-06-27
    target: "https://eprint.iacr.org/2020/800"
    author:
      - ins: M. Bellare
      - ins: W. Dai
      - ins: P. Rogaway

  Shamir:
    title: "How to share a secret"
    date: 1979-11-01
    target: "https://dl.acm.org/doi/10.1145/359168.359176"
    author:
      - ins: A. Shamir

  Poplar:
    title: "Lightweight Techniques for Private Heavy Hitters"
    date: 2022-01-04
    target: "https://eprint.iacr.org/2021/017"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai

  SGCM:
    title: "SGCM: The Sophie Germain Counter Mode"
    date: 2011-11-04
    target: "https://eprint.iacr.org/2011/326"
    author:
      - ins: M-J. O. Saarinen

  Sybil:
    title: "The Sybil Attack"
    date: 2002-10-10
    target: "https://link.springer.com/chapter/10.1007/3-540-45748-8_24"
    author:
      - ins: J. Douceur


--- abstract

Servers often need to collect data from clients that can be privacy-sensitive if
the server is able to associate the collected data with a particular user. In
this document we describe STAR, an efficient and secure threshold aggregation
protocol for collecting measurements from clients by an untrusted aggregation
server, while maintaining K-anonymity guarantees.


--- middle

# Introduction

Collecting user data is often fraught with privacy issues because without adequate
protections it is trivial for the server to learn sensitive information about the
client contributing data. Even when the client's identity is separated from the
data (for example, if the client is using the {{Tor}} network or
{{?OHTTP=I-D.ietf-ohai-ohttp}} to upload data), it's possible for the collected data
to be unique enough that the user's identity is leaked. A common solution to this
problem of the measurement being user-identifying is to make sure that the measurement
is only revealed to the server if there are at least K clients that have contributed
the same data, thus providing K-anonymity to participating clients. Such
privacy-preserving systems are referred to as threshold aggregation systems.

In this document we describe one such system, namely Distributed Secret Sharing for
Private Threshold Aggregation Reporting (STAR) {{STAR}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used:

Aggregation Server:
: An entity that would like to learn aggregated data from users.

Randomness Server:
: An entity that runs an oblivious pseudorandom function ({{!OPRF=I-D.irtf-cfrg-voprf}})
  service that allows clients to receive pseudorandom function evaluations on their
  measurement and the server OPRF key, without the Randomness Server learning anything
  about their measurement. The clients use the output as randomness to produce the
  report that is then sent to the Aggregation Server.

Anonymizing Server:
: An entity that clients use to decouple their identity (IP address) from their
messages sent to the Aggregation Server.

Client:
: The entity that provides user data to the system.

Measurement:
: The unencrypted, potentially-sensitive data that the client is asked to report.

Report:
: The encrypted measurement being sent by the client.

Auxiliary Data:
: Arbitrary data that clients may send as part of their report, but which is only
  revealed when at least K encrypted measurements of the same value are received.

REPORT_THRESHOLD:
: The minimum number of reports that an Aggregation Server needs before revealing
  client data. This value is chosen by the application.

# Cryptographic Dependencies

STAR depends on the following cryptographic protocols and primitives:

- Threshold secret sharing (TSS); {{deps-tss}}
- Oblivious Pseudorandom Function (OPRF); {{deps-oprf}}
- Key Derivation Function (KDF); {{deps-kdf}}
- Key-Committing Authenticated Encryption with Associated Data (KCAEAD); {{deps-aead}}

This section describes the syntax for these protocols and primitives in more detail.

## Threshold Secret Sharing {#deps-tss}

A threshold secret sharing scheme with the following important properties:

- Privacy: Secret shares reveal nothing unless k = REPORT_THRESHOLD shares are combined
  to recover the secret.
- Authenticity: Combining at least k = REPORT_THRESHOLD shares will only succeed if all
  shares correspond to the same underlying secret. Otherwise, it fails.

A threshold secret sharing scheme with these properties has the following API syntax:

- Share(k, msg, rand): Produce a k-threshold share of the secret
  `x` using randomness `rand`. The value k is an integer, and `msg` and `rand` are byte strings.
- Recover(k, share_set): Combine the secret shares in `share_set`, which is of size at
  least k, and recover the corresponding message `msg`. If recovery fails, this function
  returns an error.
- Nshare: The size in bytes of a secret share value.

### Finite field choice

We use traditional Shamir secret sharing (SSS) {{Shamir}} for
implementing the sharing scheme. This functionality is implemented using
a finite (Galois) field `FFp = GF(p)`, where the order `p` is a large enough
power-of-two or prime (e.g. of length greater than 32 bits). Note that
SSS is unconditionally secure, and thus the size of the field is not
important from a security perspective. As such we choose the following
prime:

~~~~
p = 2^(128) + 1451 = 340282366920938463463374607431768223907
~~~~

The value of `p` above is a well-known "safe prime" that has been
specified for usage with 128-bit Galois fields in the past {{SGCM}}.

### API implementation

We now describe the implementation of the API functions above. We
require internal usage of the following functions:

- `hash_to_field(x, n)` from {{!H2C=I-D.irtf-cfrg-hash-to-curve, Section 5}}
  for hashing `x` to `n` finite field elements in GF(p).
- `polynomial_evaluate(x, poly)` from
  {{!FROST=I-D.draft-irtf-cfrg-frost, Section 4.2.1}} for evaluating a
  given polynomial specified by `poly` on the input `x`.
- `polynomial_interpolation(points)` from
  {{!FROST=I-D.draft-irtf-cfrg-frost, Section 4.2.3}} for constructing a
  polynomial of degree `N-1` from the set `points` of size `N`.

~~~~~
def Share(k, x, rand):
  poly = [hash_to_field(x, 1)]
  poly.extend(hash_to_field(rand, k-1))
  r = FFp.random()
  return polynomial_evaluate(r, poly)

def Recover(k, share_set):
  if share_set.length < k:
    raise RecoveryFailedError
  poly = polynomial_interpolation(share_set)
  return poly[0]
~~~~~

## Verifiable Oblivious Pseudorandom Function {#deps-oprf}

A Verifiable Oblivious Pseudorandom Function (VOPRF) is a two-party protocol between client and
server for computing a PRF such that the client learns the PRF output and neither party learns
the input of the other. This specification depends on the prime-order VOPRF construction specified
in {{!OPRF=I-D.irtf-cfrg-voprf}}, draft version -10, using the VOPRF mode (0x01) from {{OPRF, Section 3.1}}.

The following VOPRF client APIs are used:

- Blind(element): Create and output (`blind`, `blinded_element`), consisting of a blinded
  representation of input `element`, denoted `blinded_element`, along with a value to revert
  the blinding process, denoted `blind`.
- Finalize(element, blind, evaluated_element, proof): Finalize the OPRF evaluation using input `element`,
  random inverter `blind`, evaluation output `evaluated_element`, and proof `proof`,
  yielding output `oprf_output` or an error upon failure.

Moreover, the following OPRF server APIs are used:

- BlindEvaluate(k, blinded_element): Evaluate blinded input element `blinded_element` using
  input key `k`, yielding output element `evaluated_element` and proof `proof`. This is equivalent to
  the Evaluate function described in {{OPRF, Section 3.3.1}}, where `k` is the private key parameter.
- DeriveKeyPair(seed, info): Derive a private and public key pair deterministically
  from a seed and info parameter, as described in {{OPRF, Section 3.2}}.

Finally, this specification makes use of the following shared APIs and parameters:

- SerializeElement(element): Map input `element` to a fixed-length byte array `buf`.
- DeserializeElement(buf): Attempt to map input byte array `buf` to an OPRF group element.
  This function can raise a DeserializeError upon failure; see {{OPRF, Section 2.1}}
  for more details.
- SerializeScalar(scalar): Map input `scalar` to a unique byte array buf of fixed
  length Ns bytes.
- DeserializeScalar(buf): Attempt to map input byte array `buf` to an OPRF scalar element.
  This function raise a DeserializeError upon failure; see {{OPRF, Section 2.1}}
  for more details.
- Ns: The size of a serialized OPRF scalar element output from SerializeScalar.
- Noe: The size of a serialized OPRF group element output from SerializeElement.

This specification uses the verifiable OPRF from {{OPRF, Section 3}} with the
OPRF(ristretto255, SHA-512) as defined in {{OPRF, Section 4.1.1}}.

## Key Derivation Function {#deps-kdf}

A Key Derivation Function (KDF) is a function that takes some source of initial
keying material and uses it to derive one or more cryptographically strong keys.
This specification uses a KDF with the following API and parameters:

- Extract(salt, ikm): Extract a pseudorandom key of fixed length `Nx` bytes from
  input keying material `ikm` and an optional byte string `salt`.
- Expand(prk, info, L): Expand a pseudorandom key `prk` using the optional string `info`
  into `L` bytes of output keying material.
- Nx: The output size of the `Extract()` function in bytes.

This specification uses HKDF-SHA256 {{!HKDF=RFC5869}} as the KDF function, where Nx = 32.

## Key-Committing Authenticated Encryption with Associated Data {#deps-aead}

A Key-Committing Authenticated Encryption with Associated Data (KCAEAD) scheme is an algorithm
for encrypting and authenticating plaintext with some additional data.
It has the following API and parameters:

- `Seal(key, nonce, aad, pt)`: Encrypt and authenticate plaintext
  `"pt"` with associated data `"aad"` using symmetric key `"key"` and nonce
  `"nonce"`, yielding ciphertext `"ct"` and tag `"tag"`.
- `Open(key, nonce, aad, ct)`: Decrypt `"ct"` and tag `"tag"` using
  associated data `"aad"` with symmetric key `"key"` and nonce `"nonce"`,
  returning plaintext message `"pt"`. This function can raise an
  `OpenError` upon failure.
- `Nk`: The length in bytes of a key for this algorithm.
- `Nn`: The length in bytes of a nonce for this algorithm.
- `Nt`: The length in bytes of the authentication tag for this algorithm.

This specification uses a KCAEAD built on AES-128-GCM {{GCM}}, HKDF-SHA256 {{HKDF}}, and
HMAC-SHA256 {{!HMAC=RFC2104}}. In particular, Nk = 16, Nn = 12, and Nt = 16. The Seal
and Open functions are implemented as follows.

~~~~~
def Seal(key, nonce, aad, pt):
  key_prk = Extract(nil, key)
  aead_key = Expand(key_prk, "aead", Nk)
  hmac_key = Expand(key_prk, "hmac", 32) // 32 bytes for SHA-256

  ct = AES-128-GCM-Seal(key=aead_key, nonce=nonce, aad=aad, pt=pt)
  tag = HMAC(key=hmac_key, message=ct)
  return ct || tag

def Open(key, nonce, aad, ct_and_tag):
  key_prk = Extract(nil, key)
  aead_key = Expand(key_prk, "aead", Nk)
  hmac_key = Expand(key_prk, "hmac", 32) // 32 bytes for SHA-256

  ct || tag = ct_and_tag
  expected_tag = HMAC(key=hmac_key, message=ct)
  if !constant_time_equal(expected_tag, tag):
    raise OpenError
  pt = AES-128-GCM-Open(key=aead_key, nonce=nonce, aad=aad, ct=ct) // This can raise an OpenError
  return pt
~~~~~

# System Overview

In STAR, clients generate encrypted measurements and send them to a single untrusted
Aggregation Server in a report. Each report is effectively a random k-out-of-n share of
the client data secret, along with some additional auxilary data. In a given amount of
time, if the Aggregation Server receives the same encrypted value from k = REPORT_THRESHOLD
clients, the server can recover the client data associated with each report. This ensures
that clients only have their measurements revealed if they are part of a larger crowd,
thereby achieving k-anonymity privacy (where k = REPORT_THRESHOLD).

Each client report is as secret as the underlying client data. That means low
entropy client data values could be abused by an untrusted Aggregation Server in a
dictionary attack to recover client data with fewer than REPORT_THRESHOLD honestly generated
reports. To mitigate this, clients boost the entropy of their data using output from an Oblivious
Pseudorandom Function (OPRF) provided by a separate, non-colluding Randomness Server.

STAR also requires use of a client Anonymizing Proxy when interacting with the Aggregation
Server so that the Aggregation Server cannot link a client report to a client which generated it.
This document does not require a specific type of proxy. In practice, proxies built on {{OHTTP}}
or {{Tor}} suffice; see {{proxy-options}} for more details.

The overall architecture is shown in {{arch}}, where `msg` is the measurement and `aux` is
auxiliary data associated with a given client. The output of the interaction is a data value
`msg` shared amongst REPORT_THRESHOLD honest clients and a list of additional auxiliary data
values associated with each of the REPORT_THRESHOLD client reports, denoted `<aux>`.

~~~~ aasvg

     +------------+         +--------------+             +-------------+
     |   Client   |         |  Randomness  |             | Aggregation |
     | (msg, aux) |         |    Server    |             |   Server    |
     +---+--------+         +------+-------+             +------+------+
         |                         |                            |
         |                         |===========\                |
         | Request(Blind(msg))     |           |                |
         +------------------------>|           | Randomness     |
         |                         | Evaluate  | Phase          |
         |           Response(...) |           |                |
         |<------------------------+           |                |
         |                         |===========/                |
         |                        ...                           |
    Generate Report                                             |
    using randomness                                            |
         |                  +--------------+                    |
         |                  |  Anonymizing |                    |
         |                  |    Proxy     |                    |
         |                  +-------+------+                    |
         | Report                   |                           |========\
         +--------------------------|-------------------------->|        |
         |                          |                           | Store  | Report
         |                          |           Acknowledgement | Report | Phase
         |<-------------------------|---------------------------+        |
         |                         ...                          |========/
         |                                                     ...
         |                                                      |
        ...                                                     |
                                                                |========\
                                                         Recover data    | Aggregation
                                                         from Reports    | Phase
                                                                |========/
                                                                v
                                                           (msg, <aux>)
~~~~
{: #arch title="System Architecture"}

In the following subsections, we describe each of the phases of STAR in more detail.

## Randomness Phase

The randomness sampled from a client data MUST be a deterministic function of the measurement.
Clients sample this randomness by running an OPRF protocol with the Randomness Server.
This section describes how the Randomness Server is configured and then how clients
interact with it for computing the randomness.

### Configuration {#randomness-configuration}

STAR clients are configured with a Randomness Server URI and the Randomness Server public key `pkR`.
Clients use this URI to send HTTP messages to the Randomness Server to complete the protocol.
As an example, the Randomness Server URI might be https://randomness.example.

The Randomness Server only needs to configure an OPRF key pair per epoch. This is
done as follows:

~~~
seed = random(32)
(skR, pkR) = DeriveKeyPair(seed, "STAR")
~~~

[[OPEN ISSUE: describe HTTP API configuration]]

### Randomness Protocol

This procedure works as follows. Let `msg` be the client's measurement to be used for deriving
the randomness `rand`.

Clients first generate the a context for invoking the OPRF protocol as follows:

~~~
client_context = SetupVOPRFClient(0x0001, pkR) // OPRF(ristretto255, SHA-512) ciphersuite
~~~

Clients then blind their measurement using this context as follows:

~~~
(blinded, blinded_element) = client_context.Blind(msg)
~~~

Clients then compute `randomness_request = SerializeElement(blinded_element)` and send it
to the Randomness Server URI in a HTTP POST message using content type "message/star-randomness-request".
An example request is shown below.

~~~
:method = POST
:scheme = https
:authority = randomness.example
:path = /
accept = message/star-randomness-response
content-type = message/star-randomness-response
content-length = Noe

<Bytes containing a serialized blinded element>
~~~

Upon receipt, the Randomness Server evaluates and returns a response.
It does so by first creating a context for running the ORPF protocol as follows:

~~~
server_context = SetupVOPRFServer(0x0001, skR, pkR) // OPRF(ristretto255, SHA-512) ciphersuite
~~~

Here, `skR` and `pkR` are private and public keys generated as described in {{randomness-configuration}}.

The Randomness Server then computes `blinded_element = DeserializeElement(randomness_request)`.
If this fails, the Randomness Server returns an error in a 4xx response to the client. Otherwise,
the server computes:

~~~
evaluated_element, proof = server_context.BlindEvaluate(sk, blinded_element)
~~~

The Randomness Server then serializes the evaluation output and proof to produce a randomness response
as follows:

~~~
evaluated_element_enc = SerializeElement(evaluated_element)
proof_enc = SerializeScalar(proof[0]) || SerializeScalar(proof[1])
randomness_response = evaluated_element_enc || proof_enc
~~~

This response is then sent to the client using the content type "message/star-randomness-response".
An example response is below.

~~~
:status = 200
content-type = message/star-randomness-response
content-length = Noe

<Bytes containing randomness_response>
~~~

Upon receipt, the client computes parses `randomness_response` to recover the evaluated element
and proof as follows:

~~~
evaluated_element_enc || proof_enc = parse(randomness_response)
evaluated_element = DeserializeElement(evaluated_element_enc)
proof = [DeserializeScalar(proof_enc[0:Ns]), DeserializeScalar(proof_enc[Ns:])]
~~~

If any of these steps fail, the client aborts the protocol. Otherwise, the client
finalizes the OPRF protocol to compute the output `rand` as follows:

~~~
rand = client_context.Finalize(msg, blind, evaluated_element, proof)
~~~

## Reporting Phase {#client-message}

In the reporting phase, the client uses its measurement `msg` with auxiliary data `aux`
and its derived randomness `rand` to produce a report for the Aggregation Server.

### Reporting Configuration

The reporting phase requires the Aggregation Server to be configured with a URI for
accepting reports. As an example, the Aggregation Server URI might be https://aggregator.example.
The Aggregation Server is both an Oblivious HTTP Target and Oblivious Gateway Resource.

Clients are also configured with an Anonymizing Proxy that clients can use to send
proxy reports to the Aggregation Server. The exact type of proxy is not specified here.
See {{proxy-options}} for more details.

### Reporting Protocol

This reporting protocol works as follows. First, the client stretches `rand` into three values
`key_seed`, `share_coins`, and `tag`, and additionally derives an KCAEAD key and nonce
from `key_seed`.

~~~
// Randomness derivation
rand_prk = Extract(nil, rand)
key_seed = Expand(rand_prk, "key_seed", 16)
share_coins = Expand(rand_prk, "share_coins", 16)
tag = Expand(rand_prk, "tag", 16)

// Symmetric encryption key derivation
key_prk = Extract(nil, key_seed)
key = Expand(key_prk, "key", Nk)
nonce = Expand(key_prk, "nonce", Nn)
~~~

The client then generates a secret share of `key_seed` using `share_coins` as randomness as follows:

~~~
rand_share = Share(REPORT_THRESHOLD, key_seed, share_coins)
~~~

[[OPEN ISSUE: what should N be for the TSS scheme?]]

The client then encrypts `msg` and `aux` using the KCAEAD key and nonce as follows:

~~~
report_data = len(msg, 4) || msg || len(aux, 4) || aux
encrypted_report = Seal(key, nonce, nil, report_data)
~~~

The function `len(x, n)` encodes the length of input `x` as an `n`-byte big-endian integer.

Finally, the client constructs a report consisting of `encrypted_report`, `rand_share`,
and `tag`, and sends this to the Anonymizing Server in the subsequent epoch, i.e., after
the Randomness Server has rotated its OPRF key.

~~~
struct {
  opaque encrypted_report<1..2^16-1>;
  opaque rand_share[Nshare];
  opaque tag[16];
} Report;
~~~

Specifically, Clients send a Report to the Aggregation Server using an HTTP POST message
with content type "message/star-report". An example message is below.

~~~
:method = POST
:scheme = https
:authority = aggregator.example
:path = /
content-type = message/star-report
content-length = <Length of body>

<Bytes containing a Report>
~~~

This message is sent to the Aggregation Server through the Anonymizing Proxy. See {{proxy-options}}
for different types of proxy options.

## Aggregation Phase

Aggregation is the final phase of STAR. It happens offline and does not require any
communication between different STAR entities. It proceeds as follows. First, the
Aggregation Server groups reports together based on their `tag` value. Let `report_set`
denote a set of at least REPORT_THRESHOLD reports that have a matching `tag` value.

Given this set, the Aggregation Server begins by running the secret share recovery algoritm
as follows:

~~~
key_seed = Recover(report_set)
~~~

If this fails, the Aggregation Server chooses a new candidate report share set and
reruns the aggregation process.

[[OPEN ISSUE: how does the server choose new candidate sets when share recovery fails?]]

Otherwise, the Aggregation Server derives the same KCAEAD key and nonce from `key_seed` to
decrypt each of the report ciphertexts in `report_set`.

~~~
key_prk = Extract(nil, key_seed)
key = Expand(key_prk, "key", Nk)
nonce = Expand(key_prk, "nonce", Nn)
~~~

Each report ciphertext is decrypted as follows:

~~~
report_data = Open(key, nonce, nil, ct)
~~~

The message `msg` and auxiliary data `aux` are then parsed from `report_data`.

If this fails for any report, the Aggregation Server chooses a new candidate report share set and
reruns the aggregation process. Otherwise, the Aggregation Server then outputs `msg` and each of
the `aux` values for the corresponding reports.

[[OPEN ISSUE: what happens if the msg is different for any two reports in the set? This should not happen if using a KCAEAD, but good to handle nevertheless]]

## Auxiliary data

In {{arch}}, `aux` refers to auxiliary or additional data that may be sent by clients, and
is distinct from the measurement data protected by the K-anonymity guarantee. Auxiliary data
is only revealed when the k-condition is met but, importantly, is not part of the k-condition
itself. This data might be unique to some or all of the submissions, or omitted entirely. This
can even be the actual measured value itself. For example: if we're measuring tabs open on a
client, then the measurement being sent can be "city: Vancouver" and the aux data can be "7"
for a particular client. The idea being, that we only reveal all the measurements once we
know that there are at least K clients with city: Vancouver.

# Anonymizing Proxy Options {#proxy-options}

The Anonymizing Proxy can be instantiated using {{OHTTP}}, {{Tor}}, or even a TCP-layer proxy.
The choice of which proxy to use depends on the application threat model. The fundamental
requirement is that the Anonymizing Proxy hide the client IP address and any other
unique client information from the Aggregation Server.

In general, there are two ways clients could implement the proxy: at the application layer,
e.g., via {{OHTTP}}, or at the connection or transport layer, e.g., via {{Tor}} or similar
systems. We describe each below.

## Application-Layer Proxy

An application-layer proxy hides client identifying information from the Aggregation Server
via application-layer intermediation. {{OHTTP}} is the RECOMMENDED option for an application-layer
proxy. {{OHTTP}} ensures that a network adversary between the client and Anonymizing Proxy
cannot link reports sent to the Aggregation Server (up to what is possible by traffic analysis).

OHTTP consists of four entities: client, Oblivious Relay Resource, Oblivious Gateway Resource,
and Target Resource. In this context, the Target Resource is the Aggregation Server. The
Aggregation Server can also act as the Oblvious Gateway Resource. Clients are configured with
the URI of the Oblivious Relay Resource, and use this to forward requests to a Oblivious
Gateway Resource. The Oblivious Gateway Resource then forwards requests to the Target as required.

## Connection-Layer Proxy

A connection-layer proxy hides client identifying information from the Aggregation Server via
connection-layer intermediation. {{Tor}} is perhaps the most commonly known example of such a proxy.
Clients can use Tor to connect to and send reports to the Aggregation Server. Other examples of
connection-layer proxies include CONNECT-based HTTPS proxies, used in systems like Private Relay
{{PrivateRelay}} and TCP-layer proxies. TCP proxies only offer weak protection in practice since
an adversary capable of eavesdropping on ingress and egress connections from the Anonymizing Proxy
can trivially link data together.

# Security Considerations {#security-considerations}

This section contains security considerations for the draft.

## Randomness Sampling {#sec-randomness-sampling}

Deterministic randomness MUST be sampled by clients to construct their STAR report, as discussed
in {{client-message}}. This randomness CANNOT be derived locally, and MUST be sampled from the
Randomness Server (that runs an {{!OPRF=I-D.irtf-cfrg-voprf}} service).

For best-possible security, the Randomness Server SHOULD sample and use a new OPRF key for each
time epoch `t`, where the length of epochs is determined by the application. The previous OPRF
key that was used in epoch `t-1` can be safely deleted. As discussed in {{leakage}}, shorter
epochs provide more protection from Aggregation Server attacks, but also reduce the
window in which data collection occurs (and hence reduce the possibility that we will have
enough reports to decrypt) while increasing the reporting latency.

In this model, for further security, clients SHOULD sample their randomness in epoch `t` and
then send it to the Aggregation Server in `t+1` (after the Randomness Server has rotated their
secret key). This prevents the Aggregation Server from launching queries after receiving the
client reports ({{leakage}}). It is also RECOMMENDED that the Randomness Server runs in
verifiable mode, which allows clients to verify the randomness that they are being served
{{!OPRF=I-D.irtf-cfrg-voprf}}.

## Oblivious Submission {#oblivious-submission}

The reports being submitted to an Aggregation Server in STAR MUST be detached from client identity.
This is to ensure that the Aggregation Server does not learn exactly what each client submits,
in the event that their measurement is revealed. This is achieved through the use of an Anonymizing
Server, which is an OHTTP Oblivious Relay Resource. This server MUST NOT collude with the Aggregation
Server. All the client responsibilities mentioned in section 7.1 of {{OHTTP}} apply.

The OHTTP Relay Resource and Randomness Server MAY be combined into a single entity, since client
reports are protected by a TLS connection between the client and the Aggregation Server. Therefore,
OHTTP support can be enabled without requiring any additional non-colluding parties. In this mode,
the Randomness Server SHOULD allow two endpoints: (1) to evaluate the VOPRF functionality that
provides clients with randomness, and (2) to proxy client reports to the Aggregation Server.
However, this increases the privacy harm in case of collusion; see {{collusion-aggregation-proxy}}.

If configured otherwise, clients can upload reports to the Aggregation Server using an existing
anonymizing proxy service such as {{Tor}}. However, use of OHTTP is likely to be the most efficient
way to achieve oblivious submission.

## Malicious Clients

Malicious clients can perform a Sybil attack on the system by sending bogus reports to the Aggregation
Server. A bogus report is one that will cause secret share recovery to fail. Aggregation Servers can
limit the impact of such clients by using higher-layer defences such as identity-based
certification {{Sybil}}.

## Malicious Aggregation Server

### Dictionary Attacks {#dictionary-attacks}

The Aggregation Server may attempt to launch a dictionary attack against the client measurement,
by repeatedly launching queries against the Randomness Server for measurements of its choice.
This is mitigated by the fact that the Randomness Server regularly rotates the VOPRF key that
they use, which reduces the window in which this attack can be launched ({{sec-randomness-sampling}}).
Note that such attacks can also be limited in scope by maintaining out-of-band protections
against entities that attempt to launch large numbers of queries in short time periods.

### Sybil Attacks

By their very nature, attacks where a malicious Aggregation Server injects clients into the
system that send reports to try and reveal data from honest clients are an unavoidable
consequence of building any threshold aggregation system. This system cannot provide
comprehensive protection against such attacks. The time window in which such attacks can
occur is restricted by rotating the VOPRF key ({{sec-randomness-sampling}}). Such attacks
can also be limited in scope by using higher-layer defences such as identity-based
certification {{Sybil}}.

## Leakage and Failure Model {#leakage}

### Size of Anonymity Set

Client reports immediately leak deterministic tags that are derived from the VOPRF output
that is evaluated over client measurement. This has the immediate impact that the size of
the anonymity set for each received measurement (i.e. which clients share the same measurement)
is revealed, even if the measurement is not revealed. As long as client reports are sent
via an {{OHTTP}} Relay Resource, then the leakage derived from the anonymity sets themselves
is significantly reduced. However, it may still be possible to use this leakage to reduce
a client's privacy, and so care should be taken to not construct situations where counts
of measurement subsets are likely to lead to deanonymization of clients or their data.

### Collusion between Aggregation and Randomness Servers {#collusion-aggregation-randomness-servers}

Finally, note that if the Aggregation and Randomness Servers collude and jointly learn the
VOPRF key, then the attack above essentially becomes an offline dictionary attack. As such,
client security is not completely lost when collusion occurs, which represents a safer mode
of failure when compared with Prio and Poplar.

### Collusion between Aggregation Server and Anonymizing Proxy {#collusion-aggregation-proxy}

As mentioned in {{oblivious-submission}}, systems that depend on a relaying server to remove
linkage between client reports and client identity rely on the assumption of non-collusion
between the relay and the server processing the client reports. Given that STAR depends on
such a system for guaranteeing that the Aggregation Server does not come to know which
client submitted the STAR report (once decrypted), the same collusion risk applies.

It's worth mentioning here for completeness sake that if the OHTTP Relay Resource and
Randomness Server are combined into a single entity as mentioned in {{oblivious-submission}},
then this worsens the potential leakage in case of collusion: if the entities responsible
for the Aggregation Server and the Randomness Server collude as described in
{{collusion-aggregation-randomness-servers}}, this results in the Aggregation Server in
effect colluding with the anonymizing proxy.

# Comparisons with other Systems

[[EDITOR NOTE: for information/discussion: consider removing before publication]]

## Private Heavy-Hitter Discovery

STAR is similar in nature to private heavy-hitter discovery protocols, such as Poplar {{Poplar}}.
In such systems, the Aggregation Server reveals the set of client measurements that are shared
by at least K clients. STAR allows a single untrusted server to perform the aggregation process,
as opposed to Poplar which requires two non-colluding servers that communicate with each other.

As a consequence, the STAR protocol is orders of magnitude more efficient than the Poplar
approach, with respect to computational, network-usage, and financial metrics. Therefore,
STAR scales much better for large numbers of client submissions. See the {{STAR}} paper for
more details on efficiency comparisons with the Poplar approach.

## General Aggregation

In comparison to general aggregation protocols like Prio {{?Prio=I-D.draft-gpew-priv-ppm}},
the STAR protocol provides a more constrained set of functionality. However, STAR is
significantly more efficient for the threshold aggregation functionality, requires only a
single Aggregation Server, and is not limited to only processing numerical data types.

## Protocol Leakage

As we discuss in {{leakage}}, STAR leaks deterministic tags derived from the client
measurement that reveal which (and how many) clients share the same measurements, even
if the measurements themselves are not revealed. This also enables an online dictionary
attack to be launched by the Aggregation Server by sending repeated VOPRF queries to the
Randomness Server as discussed in {{dictionary-attacks}}.

The leakage of Prio is defined as whatever is leaked by the function that the aggregation
computes. The leakage in Poplar allows the two Aggregation Servers to learn all heavy-hitting
prefixes of the eventual heavy-hitting strings that are output. Note that in Poplar it is
also possible to launch dictionary attacks of a similar nature to STAR by launching a
Sybil attack {{Sybil}} that explicitly injects multiple measurements that share the same
prefix into the aggregation. This attack would result in the aggregation process learning
more about client inputs that share those prefixes.

Finally, note that under collusion, the STAR security model requires the adversary to
launch an offline dictionary attack against client measurements. In Prio and Poplar,
security is immediately lost when collusion occurs.

## Support for auxiliary data

It should be noted that clients can send auxiliary data ({{auxiliary-data}}) that is
revealed only when the aggregation including their measurement succeeds (i.e. K-1 other
clients send the same value). Such data is supported by neither Prio, nor Poplar.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank the authors of the original {{STAR}} paper, which forms the basis for this document, as well as the following contributors: Christopher A. Wood.
