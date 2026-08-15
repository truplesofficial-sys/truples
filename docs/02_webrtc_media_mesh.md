# WebRTC P2P Mesh Architecture & Real-Time Media Protocols

## 1. Decentralized Media Topology
Truples utilizes a direct **Peer-to-Peer (P2P) WebRTC Mesh** topology optimized for 1:1 and private small-group communication, deliberately bypassing centralized Media Control Units (MCU) or Selective Forwarding Units (SFU) to eliminate central surveillance and interception risks.

```
       [ Client A ] <================ DTLS/SRTP ================> [ Client B ]
            ^                                                           ^
            |                                                           |
            +================= DTLS/SRTP ===============================+
                                   |
                                   v
                              [ Client C ]
```

## 2. Media Channel Security
- **Signaling Layer**: WebSocket over TLS 1.3 (WSS) utilizing STOMP framing for SDP Offer/Answer exchanges and ICE candidate gathering.
- **Media Stream Encryption**:
  - `DTLS 1.2 / 1.3` (Datagram Transport Layer Security) handshake for session key establishment.
  - `SRTP` (Secure Real-time Transport Protocol) with `AES-CM-128` / `AES-GCM-256` for encrypted audio and video packet streaming.
- **STUN / TURN Fallback**: Distributed NAT traversal infrastructure enforcing authenticated TURN relays with temporary credential rotation.

## 3. Asynchronous OS Wakeup & Cold-Boot Synchronization
- **Platform Telephony**: Integrated with Android `ConnectionService` (Telecom Framework) and iOS `CallKit`.
- **On-Connect Recovery Hook**: Upon cold-boot or background activation, clients execute atomic SDP offer re-negotiation hooks (`group-request-offer`) to guarantee zero call packet loss.
