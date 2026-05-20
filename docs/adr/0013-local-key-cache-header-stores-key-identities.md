# Local key cache header stores key identities

SSHWarden's local key cache will store key identities in a readable header so a remembered device can start locked while still allowing SSH clients to list available keys. The encrypted payload contains private key material protected by the local cache key; exposing public keys, display names, key identifiers, and sync metadata in the header is accepted for baseline usability, with privacy-oriented display options left for future work.
