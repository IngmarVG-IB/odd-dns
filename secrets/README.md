# Key material

Two *different* keys are used, and they must not be confused:

1. **`txfr-local`** (a BIND TSIG key) -- authenticates the loopback AXFR
   that `zone_diode_tx.py` pulls from the hidden primary. Lives only in
   `named.conf.inside` and never leaves the inside host. Generate with:

   ```bash
   tsig-keygen txfr-local
   ```

2. **`diode.key`** (a raw pre-shared key, not TSIG) -- HMAC-authenticates
   every frame that crosses the diode itself. Both `zone_diode_tx.py` and
   `zone_diode_rx.py` need an identical copy. Generate with:

   ```bash
   openssl rand -hex 32 > diode.key
   ```

`diode.key` cannot be provisioned over the diode after the fact for a
*first* deployment -- copy it to both hosts via whatever out-of-band,
approved channel your accreditation process already uses for cross-domain
solution key material (approved removable media, a provisioning step done
before the hosts are separated by the diode, etc.). Rotating it later is
easier: a new key can be pushed one-way, HMAC'd under the *old* key, and
the receiver can adopt it and retire the old one after the next confirmed
cycle -- this repo does not implement that ratchet, but the protocol's
manifest frame has room to carry it as an extension.

Nothing under this directory except this README should be committed --
see `.gitignore` at the repo root.
