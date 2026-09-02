# RPZ Feasibility Analysis

## Scenario: 5 Million RPZ records

**Zone size estimate:**
- RPZ record (serialized): ~100 bytes (CNAME form is typical)
- 5M records × 100 bytes = ~500 MB zone file

**Transmission math (at 5ms pacing, repeats=3):**
- Chunk size: 1100 bytes (after framing overhead)
- Chunks needed: 454,546
- Total UDP frames: 1,363,641 (chunks × 3 repeats + manifest repeats)
- **Total cycle time: ~114 minutes**

**Reality check — what's the actual bottleneck?**

1. **AXFR pull from the hidden primary** (the initial step on the high side):
   - 500 MB over loopback TCP at typical goodput (~100 MB/s) = ~5 seconds
   - This is 1000x faster than the diode carousel.

2. **The diode carousel** (the cross-domain step):
   - 114 minutes to send one full cycle
   - Perfectly fine. Default `--interval 300` (5 min) means it re-broadcasts.
   - A lost cycle is superseded by the next one in ~2 hours worst-case.

3. **Reassembly and validation on the low side:**
   - Just hash-checking 500 MB: ~100ms with SHA-256
   - named-checkzone on 500 MB: depends on your hardware, but typically under 1 second
   - Atomic install: microseconds

**Conclusion:** YES, large RPZ zones (5M+ records) work fine. The only constraint is **elapsed time for a full cycle**, not feasibility. For a 5M-record RPZ:

- If you need updates to propagate faster than every 2 hours, you'd want to:
  - Reduce `--repeats` (lower redundancy, but still converges; carousel picks it up)
  - Increase `--pacing-ms` to send faster (depends on your diode's bitrate)
  - Use real FEC instead of naive redundancy (external enhancement, not in this PoC)

- The AXFR source-pull is never the constraint — it completes in seconds.

## For production RPZ deployments:

1. **Monitoring is critical** — with a 2-hour convergence window, a broken cycle isn't immediately obvious. Alert if rx logs show no verified cycle in 3× the interval.

2. **Serial ratchet matters even more** — you don't want accidental rollbacks on large zones; that's built in and tested.

3. **Atomic install is essential** — BIND must never see a partial zone file. The code uses `os.replace()` which is atomic on POSIX/Windows within a filesystem; verify on your target OS.

4. **CPU at 5M records** — named-checkzone and BIND's load are both linear. Test on your actual hardware before production.

**Bottom line:** This design scales to enterprise RPZ sizes without architectural changes. The carousel's 2-hour worst-case convergence is by design (no feedback channel), and it's acceptable for RPZ because most RPZ updates are for new malware domains (which batch up over hours anyway) rather than real-time rate-limiting.
