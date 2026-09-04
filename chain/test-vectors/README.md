# BP52-CHAIN-v1 test vectors

These text fixtures are intentionally simple to consume from independent
implementations. Integers are decimal unless a column is explicitly labelled
hexadecimal. The Rust tests parse these files rather than duplicating their
expected values in source.

`poker-v1.txt` covers straight flush (including wheel), four of a kind, full
house, straight, flush, two pair, and one pair score packing. The exhaustive
Rust campaign separately evaluates all 2,598,960 distinct five-card hands.
