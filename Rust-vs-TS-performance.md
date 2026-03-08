# Benchmark Comparison Report

Generated: 2026-03-08 08:01:07

| Benchmark | TS avg (ms) | Rust avg (ms) | Speedup | Status |
|-----------|-------------|---------------|---------|--------|
| BigNumber mul large | 0.7828 | 1.7906 | 0.4x | **SLOWER** |
| BigNumber add large | 30.0818 | 1.1050 | 27.2x | OK |
| BN toArray big | 0.7966 | 0.0118 | 67.6x | OK |
| BN toArray little | 0.8473 | 0.0147 | 57.5x | OK |
| BN fromBytes big | 0.7052 | 0.0403 | 17.5x | OK |
| BN fromBytes little | 0.7393 | 0.0436 | 17.0x | OK |
| BN fromScriptNum | 0.7361 | 0.0440 | 16.7x | OK |
| ECC Point.mul | 0.3623 | 0.4258 | 0.9x | OK |
| ECC ECDSA.sign (scalar bench) | 0.7945 | 0.4811 | 1.7x | OK |
| ECC ECDSA.verify (scalar bench) | 1.5328 | 0.5617 | 2.7x | OK |
| ECDSA sign | 0.8141 | 0.4805 | 1.7x | OK |
| ECDSA verify | 1.5379 | 1.0586 | 1.5x | OK |
| Script findAndDelete 4000 chunks 2% | 0.0684 | 0.0155 | 4.4x | OK |
| Script findAndDelete 8000 chunks 5% | 0.2536 | 0.0361 | 7.0x | OK |
| Script findAndDelete 8000 chunks 20% | 0.6981 | 0.0671 | 10.4x | OK |
| Script findAndDelete 2000 chunks 300B | 0.0671 | 0.0188 | 3.6x | OK |
| Script findAndDelete 12000 chunks 1% | 0.2229 | 0.0433 | 5.2x | OK |
| Script serialization from_binary | 1.5847 | 0.1320 | 12.0x | OK |
| SymmetricKey encrypt large 2MB | 849.4002 | 131.0166 | 6.5x | OK |
| SymmetricKey decrypt large 2MB | 823.6411 | 130.5731 | 6.3x | OK |
| SymmetricKey encrypt 50 small | 3.6439 | 0.6306 | 5.8x | OK |
| SymmetricKey decrypt 50 small | 3.4863 | 0.4688 | 7.4x | OK |
| SymmetricKey encrypt 200 medium | 88.1460 | 13.8122 | 6.4x | OK |
| SymmetricKey decrypt 200 medium | 85.4414 | 13.5647 | 6.3x | OK |
| Transaction deep chain | 176.0855 | 51.7768 | 3.4x | OK |
| Transaction wide | 183.4866 | 52.0469 | 3.5x | OK |
| Transaction large 50x50 | 91.3650 | 26.7039 | 3.4x | OK |
| Transaction nested | 51.8053 | 23.3536 | 2.2x | OK |
| Atomic BEEF serialize | 0.6432 | 0.1044 | 6.2x | OK |
| Atomic BEEF deserialize | 1.2814 | 0.9671 | 1.3x | OK |
| Reader/Writer mixed ops | 0.0970 | 0.0350 | 2.8x | OK |
| Reader/Writer large payloads | 17.1340 | 1.6246 | 10.5x | OK |
| Reader/Writer 3000 small | 0.6016 | 0.1779 | 3.4x | OK |
| Reader/Writer 400 medium | 8.6814 | 0.7294 | 11.9x | OK |
| SHA-256 32B | 0.0015 | 0.0002 | 8.6x | OK |
| SHA-256 1KB | 0.0059 | 0.0027 | 2.1x | OK |
| SHA-256 1MB | 4.9084 | 2.6155 | 1.9x | OK |
| SHA-512 32B | 0.0027 | 0.0002 | 11.1x | OK |
| SHA-512 1KB | 0.0118 | 0.0020 | 6.0x | OK |
| SHA-512 1MB | 9.7900 | 1.7915 | 5.5x | OK |
| RIPEMD-160 32B | 0.0007 | 0.0002 | 3.8x | OK |
| RIPEMD-160 1KB | 0.0075 | 0.0032 | 2.4x | OK |
| RIPEMD-160 1MB | 7.7856 | 3.0854 | 2.5x | OK |
| HMAC-SHA256 1KB | 0.0074 | 0.0032 | 2.3x | OK |
| HMAC-SHA512 1KB | 0.0160 | 0.0027 | 5.9x | OK |
| ECIES Electrum encrypt 32B | 0.0185 | 0.0108 | 1.7x | OK |
| ECIES Electrum encrypt 1KB | 0.0731 | 0.0181 | 4.0x | OK |
| ECIES Electrum encrypt 64KB | 4.5145 | 0.4982 | 9.1x | OK |
| ECIES Electrum decrypt 32B | 0.0336 | 0.0666 | 0.5x | **SLOWER** |
| ECIES Electrum decrypt 1KB | 0.0869 | 0.0788 | 1.1x | OK |
| ECIES Electrum decrypt 64KB | 4.2368 | 0.8990 | 4.7x | OK |
| ECIES Bitcore encrypt 32B | 0.0190 | 0.0119 | 1.6x | OK |
| ECIES Bitcore encrypt 1KB | 0.0879 | 0.0206 | 4.3x | OK |
| ECIES Bitcore encrypt 64KB | 5.4265 | 0.6202 | 8.7x | OK |
| ECIES Bitcore decrypt 32B | 0.0930 | 0.0664 | 1.4x | OK |
| ECIES Bitcore decrypt 1KB | 0.1593 | 0.0835 | 1.9x | OK |
| ECIES Bitcore decrypt 64KB | 5.0487 | 1.1906 | 4.2x | OK |

## Summary

- **Total mappings:** 57
- **Matched (both sides):** 57
- **TS only:** 0
- **Rust only:** 0
- **Rust slower than TS:** 2 (flagged with **SLOWER**)
