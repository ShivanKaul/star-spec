---
title: "STAR: Distributed Secret Sharing for Private Threshold Aggregation Reporting"
abbrev: "STAR"
category: std

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

informative:
  STAR:
    title: "STAR: Distributed Secret Sharing for Private Threshold Aggregation Reporting"
    date: 2021-12-08
    target: "https://arxiv.org/abs/2109.10074"
    author:
      - ins: A. Davidson
      - ins: P. Snyder
      - ins: E. Quirk
      - ins: J. Genereux
      - ins: B. Livshits
  Tor:
    title: "Tor: The Second-Generation Onion Router"
    date: 2004
    target: "https://svn-archive.torproject.org/svn/projects/design-paper/tor-design.pdf"
    author:
      - ins: R. Dingledine
      - ins: N. Mathewson
      - ins: P. Syverson

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


--- abstract

Servers often need to collect data from clients that can be privacy-sensitive if the server is able to associate the collected data with a particular user. In this document we describe STAR, an efficient and secure threshold aggregation protocol for collecting measurements from clients by an untrusted aggregation server, while maintaining K-anonymity guarantees.


--- middle

# Introduction

Collecting user data is often fraught with privacy issues because without adequate protections it is trivial for the server to learn sensitive information about the client contributing data. Even when the client's identity is separated from the data (for example, if the client is using the {{Tor}} network or {{?OHTTP=I-D.thomson-http-oblivious}}), it's possible for the collected data to be unique enough that the user's identity is leaked. A common solution to this problem of the measurement being user-identifying/sensitive is to make sure that the measurement is only revealed to the server if there are at least K clients that have contributed the same data, thus providing K-anonymity to participating clients. Such privacy-preserving systems are referred to as threshold aggregation systems.

In this document we describe one such system, namely Distributed Secret Sharing for Private Threshold Aggregation Reporting (STAR) {{STAR}}, that is currently deployed in production by the {{Brave}} browser.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The following terms are used:

Aggregation Server:
: An entity that provides some tool/software, that would like to learn aggregated data points from their user-base.

Client:
: The entity that uses the tool.

Measurement:
: The unencrypted, potentially-sensitive data point that the client is asked to report.

Message:
: The encrypted measurement being sent by the client.

Auxiliary Data:
: Arbitrary data that clients may send as part of their message, but which is only revealed when at least K encrypted measurements of the same value are received.

# System Overview

## Objective

In STAR, clients generate `encrypted` measurements, that they send to a single untrusted aggregation server. In a given amount of time, if the aggregation server receives the same encrypted value from K clients (i.e. K values), the server is able to decrypt the value. This ensures that clients only have their measurements revealed if they are part of a larger crowd. This allows the client to maintain K-anonymity, when paired with mechanisms for removing client-identifying information from their requests.

## System Architecture

The overall system architecture is shown in {{arch}}, where x is the measurement and aux is auxiliary data.

~~~~

       Client (x, aux)                  Aggregation Server
         |                                     |
         |                                     |
         |                                     |
 sample_rand(x, epoch) => rand                 |
         |                                     |
         |                                     |
         |                                     |
 encrypt(x, aux; rand) => msg                  |
         |                                     |
         |                                     |
         |                                     |
         |---------------  msg   ------------> |
         |                                     |
         |                                     |
         |                             If Kth instance of msg,
         |                             decrypt(msg) => (x, aux)
         |                                     |
         |                                     |
         |                                     |
         |                                     |
~~~~
{: #arch title="System Architecture"}

<!--- https://textik.com/#825ddce1208e2bc3 -->

The main goal in the STAR protocol is to have the aggregation performed by a single untrusted server, without requiring communication with any other non-colluding entities. In order for the aggregation to succeed, clients must send messages that are consistent with other client messages. This requires sampling randomness that is equivalent when clients share the same measurement.

## Auxiliary data

In {{arch}}, `aux` refers to auxiliary or additional data that may be sent by clients, and is distinct from the measurement data protected by the K-anonymity guarantee. Auxiliary data is only revealed when the k-condition is met but, importantly, is not part of the k-condition itself. This data might be unique to some or all of the submissions, or omitted entirely. This can even be the actual measured value itself. For example: if we're measuring tabs open on a client, then the measurement being sent can be "city: Vancouver" and the aux data can be "7" for a particular client. The idea being, that we only reveal all the measurements once we know that there are at least K clients with city: Vancouver.

## Randomness sampling

The randomness `rand` sampled for each message MUST be a deterministic function of the measurement. Either the client MAY sample the randomness directly by computing a randomness extractor over their measurement, or they MAY sample it as the output of an exchange with a separate server that implements a partially oblivious pseudorandom function protocol {{!OPRF=I-D.irtf-cfrg-voprf}}}. We discuss both cases more throughly in {{sec-randomness-sampling}}.

## Measurement Encryption

The client measurement encryption process involves the following steps.

- Sample 48-bytes of randomness `rand` deterministically from their measurement `x` (as described in {{sec-randomness-sampling}}).
- The client parses `rand` as three 16-byte chunks: `r1`, `r2`, and `r3`.
- The client samples a share `s` of `r1` from a K-out-of-N secret sharing scheme based on Lagrange interpolation, such as {{ADSS}}. This process involves `r2` as consistent randomness for generating the coefficients for the polynomial. The client must then use independent local randomness for determining the point at which to evaluate the polynomial, and generate their share.
- The client derives a symmetric encryption key, `key`, from `r1`.
- The client encrypts the concatenation of `x` and `aux` into a ciphertext `c`.
- The client then generates the message to send to the server as the tuple `(c,s,r3)`.

## Server Aggregation

The server computes the output of the aggregation by performing the following steps.

- Group client messages together depending on whether they share the same value `r3`.
- For any subset of client messages greater that is smaller than `K`:
  - Abort.
- Otherwise:
  - Run secret share recovery on the set of client-received shares `s` to reveal `r1`.
  - Derive `key` from `r1`.
  - Decrypt each ciphertext `c` to retrieve `x` and `aux`.
  - Check that each decrypted `x` value is equivalent.
  - Output `x` and the set of all auxiliary data.

# Comparisons with other Systems

(for information/discussion: consider removing before publication)

## Private Heavy-Hitter Discovery

STAR is similar in nature to private heavy-hitter discovery protocols, such as Poplar {{Poplar}}. In such systems, the aggregation server reveals the set of client measurements that are shared by at least K clients. The STAR protocol is orders of magnitude more efficient than the Poplar approach, with respect to computational, network-usage, and financial metrics. Therefore, STAR scales much better for large numbers of client submissions. Moreover, STAR allows a single untrusted server to perform the aggregation process, as opposed to Poplar which requires two non-colluding servers.

## General Aggregation

In comparison to general aggregation protocols like Prio {{?Prio=I-D.draft-gpew-priv-ppm}}, the STAR protocol provides a more constrained set of functionality. However, STAR is significantly more efficient for the threshold aggregation functionality, requires only a single aggregation server, and is not limited to only processing numerical data types.

## Protocol leakage

As we discuss in {{leakage}}, STAR leaks which (and how many) clients share the same measurements, even if the measurements themselves are not revealed. The leakage of Prio is defined as whatever is leaked by the function that the aggregation computes. The leakage in Poplar allows the two aggregation servers to learn all heavy-hitting prefixes of the eventual heavy-hitting strings that are output. Depending on the nature of the aggregation, it may be possible to utilize this leakage to harm the privacy of clients and client data that is included in the aggregation.

## Support for auxiliary data

It should be noted that clients can send auxiliary data ({{auxiliary-data}}) that is revealed only when the aggregation including their measurement succeeds (i.e. K-1 other clients send the same value). Such data is supported by neither Prio, nor Poplar.

# Security Considerations {#security-considerations}

## Randomness Sampling {#sec-randomness-sampling}

If clients sample randomness from their measurement directly, then security of the encryption process is dependent on the amount of entropy in the measurement input space. In other words, it is crucial for the privacy guarantees provided by this protocol that the aggregation server cannot simply iterate over all possible encrypted values and generate the K values needed to decrypt a given client's measurement. If this requirement does not hold, then the server can do this easily by locally evaluating the randomness derivation process on multiple measurements.

For better security guarantees, it is RECOMMENDED that clients sample their randomness as part of an interaction with an independent entity (AKA `randomness server`) running a partially oblivious pseudorandom function protocol. In such an exchange, the client submits their measurement as input, and learns `rand = POPRF(sk,x;t)` as the randomness, where `sk` is the POPRF secret key, and `t` is public metadata that dictates the current epoch. Sampling randomness in this way restricts the aggregation server to only being able to run the previous attack as an online interaction with the randomness server.

For further security enhancements, clients SHOULD sample their randomness in epoch `t` and then send it to the aggregation server in `t+1` (after the randomness server has rotated their secret key). This prevents the aggregation server from being after receiving the client messages, which shortens the window of the attack. It is also RECOMMENDED that the randomness server runs in verifiable mode, which allows clients to verify the randomness that they are being served {{!OPRF=I-D.irtf-cfrg-voprf}}.

An alternative to using a partially oblivious pseudorandom function protocol is to instead use a standard verifiable OPRF (VOPRF), and ensure that a fresh key is sampled and used in each epoch `t`. Keys for previous epochs can be safely deleted. Deleting keys in this way reduces the window in which corruption of the randomness server by the aggregation server can harm previous client submissions (i.e. providing forward-secrecy).

## Cryptographic Choices

- All encryption operations MUST be carried out using a secure symmetric authenticated encryption scheme.
- The secret sharing scheme MUST be information-theoretically secure, and SHOULD based upon traditional K-out-of-N Shamir secret sharing.
- For functionality reasons, secret sharing operations SHOULD be implemented in a finite field where collisions are unlikely (e.g. of size 128-bits). This is to ensure that clients do not sample identical shares of the same value.
- Client messages MUST be sent over a secure, authenticated channel, such as TLS.

## Oblivious Submission

Clients SHOULD ensure that their message submission is detached from their identity. This is to ensure that the aggregation server does not learn exactly what each client submits, in the event that their measurement is revealed. This can be achieved by having the clients submit their messages via an {{?OHTTP=I-D.thomson-http-oblivious}} proxy. Note that the OHTTP proxy and randomness server can be combined into a single entity, since client messages are protected by a TLS connection between the client and the aggregation server.

## Leakage

Client messages immediately leak the size of the anonymity set for each received measurement (i.e. which clients share the same measurement), even if the measurement is not revealed. As long as client messages are sent via an {{?OHTTP=I-D.thomson-http-oblivious}} proxy, then the leakage derived from the anonymity sets themselves is significantly reduced. However, it may still be possible to use this leakage to reduce a client's privacy, and so care should be taken to not construct situations where counts of measurement subsets are likely to lead to deanonymization of clients or their data.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank the authors of the original {{STAR}} paper, which forms the basis for this document.
