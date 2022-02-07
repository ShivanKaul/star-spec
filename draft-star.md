---
title: "STAR: Distributed Secret Sharing for Private Threshold Aggregation Reporting"
abbrev: "STAR"
category: std

docname: draft-star-latest
ipr: trust200902
area: SEC

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    name: "Shivan Kaul Sahib"
    organization: Brave Software
    email: "shivankaulsahib@gmail.com"

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
      
  Brave:
    title: Brave Browser
    target: https://brave.com

--- abstract

Servers often need to collect data from clients that can be privacy-sensitive if the server is able to associate the collected data with a particular user. In this document we describe STAR, an efficient and secure threshold aggregation protocol for collecting measurements from clients by an untrusted server while maintaining k-anonymity guarantees.


--- middle

# Introduction

Collecting user data is often fraught with privacy issues because without adequate protections it is trivial for the server to learn sensitive information about the client contributing data. Even when the client's identity is separated from the data (for e.g. if the client is using the Tor network or {{!OHTTP=I-D.thomson-http-oblivious}}), it's possible for the collected data to be unique enough that the user's identity is leaked. A common solution to this problem of the measurement being user-identifying/sensitive is to make sure that the measurement is only revealed to the server if there are at least K clients that have contributed the same data, thus providing K-anonymity to participating clients. Such privacy-preserving systems are referred to as threshold aggregation systems.

In this document we describe one such system, namely Distributed Secret Sharing for Private Threshold Aggregation Reporting (STAR) {{STAR}}, that is currently deployed in production by the {{Brave}} browser. This document describes the single-server model, where we assume that the client input space is sufficiently-random (see {{security-considerations}}).

# Conventions and Definitions

{::boilerplate bcp14-tagged}

[TODO] The following terms are used:

Measurement:
: The unencrypted, potentially-sensitive measurement that the client wants to report.

Message:
: The encrypted measurement being sent by the client.

Client
Auxiliary Data
Epoch
Aggregation Server


# System Overview

In STAR, clients generate encrypted measurements that they send to a single untrusted server, referred to as the aggregation server. In a given amount of time, if the aggregation server receives the same encrypted value from K clients (i.e. K values), the server is able to decrypt the value.

The overall system architecture is shown in {{arch}}, where x is the measurement and aux is auxiliary data.
                                                                                                     
~~~~
                                                                                                     
       Client (x, aux)                  Aggregation Server                                            
         |                                     |                                                      
         |                                     |                                                      
         |                                     |                                                      
         |                                     |                                                      
 encrypt(x, aux) => msg                        |                                                      
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


# Protocol Definition

A single encoded measurements is sent during a time-period (called epoch) by each client. The aggregation server should be able to reveal all those encoded measurements (and any auxiliary data) that are received at least K times. The threshold K >> 1 is public information.

TODO

# Comparisons with other Systems




# Security Considerations {#security-considerations}

This version of the STAR protocol makes the critical assumption that for the type of measurement being collected, clients can securely generate enough randomness from the measurement input space itself. In other words, it is crucial for the privacy guarantees provided by this protocol that the aggregation server cannot simply iterate over all possible encrypted values and generate the K values needed to decrypt a given client's measurement.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
