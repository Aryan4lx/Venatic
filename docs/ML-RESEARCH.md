# ML for Threat Hunting - David Hoelzer research synthesis

Sources: 7 Hoelzer videos (transcripts in `research/hoelzer/`, fetched via Invidious
captions API), his GitHub repos (DavesPythonFails, SEC595_Extras, ShowMeThePackets).
Target video: SANS DFIR Summit keynote "Threat Hunting: Old Data, New Tricks!".

## His core philosophy (the "what he says")

1. **"Old data, new tricks"** - every technique uses data you already collect
   (NetFlow/firewall logs, Zeek dns.log). "There is nothing you need to buy."
2. **ML shows you where to look, it doesn't verdict.** "I had a million queries,
   but how many things do I have to look at? Nine." Design for triage, accept
   false positives ("a human's not going to find it all either").
3. **"It's just math, not reasoning."** No autonomous defense. Vendor "AI" hype
   = an AI winter incoming; ask of any product: what are its features and what
   trains it?
4. **No long baselines.** Products that learn 6 months of "normal" learn the
   incumbent threat as normal (median dwell time > 6 months). His systems
   bootstrap from a couple of days of capture.
5. **Behaviors, not indicators.** Known-bad lists are trivial to defeat
   (reconfigure iodine -> drops off every list). Hunt shapes and patterns.
6. **The model is the easy part.** "The actual machine learning part is really
   the easiest part... the time consuming part is getting the data structured."
   Feature engineering is where analysts add value.

## Techniques he demonstrates (and what they need)

| Technique | Data | Method | Result he shows |
|---|---|---|---|
| FFT beaconing | NetFlow / firewall logs -> conn counts per time bin (48h+), per host | Discrete Fourier transform; ignore DC spike at 0; dominant non-DC frequency = beacon; coarse bins absorb jitter | Beacon every ~20min / hourly found; SEC595 students found 5 infected machines in their own firewall logs overnight |
| DBSCAN DNS clustering | ~1M unique Zeek dns.log qnames (known-bad filtered), engineered numeric features ( undisclosed, ~15min of work), PCA to 3D for viz | Density-based clustering (outliers don't distort) | 1M queries -> 9 clusters; iodine C2 always lands in its own cluster regardless of its domain config |
| Protocol classifier | First 16 bytes of client stream, hex -> 128 bit-features (bit expansion preserves flag bits; DNS 0x81 vs 0xC1 differ only in bit 8) | Keras dense net (64/32/..., RMSprop, 5 epochs, batch 32), 596k rows, 13 protocols | 99.8% val accuracy; anomaly = max softmax confidence < 0.95 ("if it doesn't know, it's an anomaly"); confidence = triage rank |
| Autoencoder protocol anomaly | Same payload features | Per-protocol autoencoder, reconstruction loss threshold; bootstrap from days of capture; add protocol by sampling | Production at his MSSP; true-vs-other losses "linearly separable"; build time ~2h |
| Log-line autoencoder ("the real way") | Raw log lines (BPE tokenizer, timestamps stripped) | Embedding -> Conv1D -> bottleneck -> deconv; alert on reconstruction MAE | Flags "failed logon attempt", "unknown operand" style anomalies |
| Moving sigma-band baseline | Any per-host time series | Sliding mean +/- 1 sigma | Simple, in `ShowMeThePackets/sample.avg.py` |
| CNN binary-as-image | 128x128 byte block of files | CNN triage | 88% test accuracy; IR-time malware triage (out of scope for network logs) |
| IR NetFlow pivot | NetFlow after compromise date | contacts-after-date -> profile (ports/bytes/protocol) -> match profile elsewhere | Classic pivot recipe, no ML |

## Key implementation details worth copying

- **Bit-expansion encoding:** hex byte -> 8 bits, values in [0,1]; preserves
  bitfields (protocol flags) that byte-value scaling destroys.
- **Shuffle before split** (TF validation_split takes the LAST rows - grouped
  data makes validation garbage).
- **CSV overwrite, never append** when regenerating training data.
- **Banners repeat:** his 16-byte corpus shows port 22 is literally always
  `SSH-1.99-OpenSSH_1.5\r\n` - exact-prefix matching catches most, ML the rest.
- **FFT bins vs jitter:** lower sampling rate = wider frequency bins; jittered
  beacons stay inside one bin and still spike.
- **DC offset:** first FFT bin is an artifact on real-valued input; ignore it.
- His `classify.zeek` (ShowMeThePackets): `string_to_ascii_hex(sub_bytes(bytes,0,16))`
  published over Broker - the sensor-side pattern if we ever want payload
  fingerprints.
- **DNS diffing is his canonical outbound detection too** (`alternativeOutWithNoDNS.zeek`,
  `anomalousOutbound.zeek`): alert on outbound conns to IPs never resolved via
  DNS, 7-day expiring set + whitelist. Validates venatic's core design.
- Analyst feedback loops: ML maturity level 3 ("learn from analyst FPs") is his
  future vision, with a blind-spot warning: auto-suppression can hide the
  nuance a human would have caught.

## What this means for venatic (decision inputs)

Implementable NOW, pure TypeScript, zero new deps, on data we already import:
1. **`hunt fft-beacons`** - per-host time-binned conn counts (events table has
   ts) -> DFT (small TS implementation) -> dominant non-DC frequency + period.
   Complements interval-CV: catches jittered beacons whose CV is too high.
2. **`hunt dns-clusters`** - feature per qname (length, label entropy, digit
   ratio, unique-char ratio, max label len, bigram rarity vs english), pure-TS
   DBSCAN (~100 lines), report clusters with samples + sizes; 2D PCA for the
   dashboard scatter. Population-level "group the weird" triage.
3. **Sigma-band volume baseline** - per-host hourly band vs own history
   (upgrade to current global-median volume hunt).

Needs new data or deps (defer, needs user decision):
- Protocol classifier / payload autoencoders need payload bytes we don't store
  (Zeek conn.log has no payload) -> requires a Zeek sensor script exporting
  first-N-bytes (his classify.zeek pattern) - "bring your own sensor".
- Real NN training in Node = TensorFlow.js (heavy) or Python sidecar (new
  runtime). His own advice: pipeline first; the model is minutes.
- Log-line autoencoder needs raw-line retention (we parse into structured
  rows; would add a raw column + new hunt).

## Fact-check list (his claims, unverified)
- DBSCAN = "Density-Based Spatial Clustering of Applications with Noise" (he
  garbles it twice).
- Iodine default domain: keynote says `micr0soft...`, talk 2 corrects to
  `micro...`. His "always its own cluster" is his experiment, not published.
- Binary-as-image malware papers: lineage is Nataraj et al. 2011.
- His numbers (88% CNN, 99.8% classifier, 5 found machines) are demo numbers,
  not peer-reviewed.
- Corelight "strips Zeek scripting" claim is overstated for current sensors.
