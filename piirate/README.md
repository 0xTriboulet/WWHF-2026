# piirate

**piirate.exe** — rip PII out of a whole directory tree, on-device, no
network, **single-file**: the only runtime dependency is Windows' *inbox*
`C:\Windows\System32\onnxruntime.dll` (ONNX Runtime 1.17.1 on Win11
24H2/25H2), loaded at run time with `LoadLibrary` — the exe imports only
`KERNEL32.dll` + `msvcrt.dll`.

A standalone CLI that recursively scans a directory for PII using a GLiNER
span-level NER model (`blinkwrite-ai/gliner-small-pii-onnx-int8`, Apache-2.0)
run through the **ONNX Runtime C API** (`OrtGetApiBase()` +
`GetApi(17)` — every call piirate uses predates API v17). The model weights
are embedded as raw bytes in C source (`include/pii_model_partNN.h`); the tokenizer
(SentencePiece/Unigram over DeBERTa-v3-small vocab) is a from-scratch C89 port
of the HuggingFace `tokenizers` pipeline. Pure C89, MinGW-w64, strict flags,
clang-tidy/clang-format clean.

> **Code-flow diagram:** `flow.html` — mermaid flowchart of the binary,
> derived 1:1 from the current source (mermaid CDN renders it).

## Usage

```
piirate.exe <directory> [--threshold 0.2] [--labels "a,b,c"] [--max-file-mb 4]
```

Recursively scans every readable file under `<directory>`, runs the text
through the embedded GLiNER PII model, and prints findings to **stdout**,
one per line:

```
<path> -> <label> (score): "<span>"
```

Examples:

```
piirate.exe C:\Users\jdoe\Documents
piirate.exe C:\logs --threshold 0.5
piirate.exe C:\dump --labels "email address,phone number,credit card number"
piirate.exe C:\bigfiles --max-file-mb 8
```

Progress and the final summary go to stderr. Unreadable files are skipped
(reported on stderr). Files larger than `--max-file-mb` MB are truncated at
the cap. Text decoding covers UTF-8 (BOM optional), UTF-16LE with BOM, and
a heuristic UTF-16LE without BOM; anything else is scanned as raw bytes.

Exit codes: `0` scan ok (zero findings is success) · `1` usage ·
`2` not a readable directory · `4` init/runtime error.

Defaults (from the model's README, tuned for chat/email prose): 17 labels —
`phone number, email address, credit card number, address, social security
number, date of birth, bank account number, password, pin code, ip address,
dollar amount, passport number, driver license number, tax id, api key,
access token, secret key` — at score threshold **0.2**.

### Requirements

- **Windows 11 24H2+ with the inbox ONNX Runtime** — the only runtime
  dependency is `C:\Windows\System32\onnxruntime.dll` (ORT 1.17.x on
  24H2/25H2), loaded with `LoadLibrary` at run time; nothing is linked at
  build time. If the box lacks the DLL the exe exits `4` with a clear
  message (Windows Server SKUs and older Win10 builds don't carry it).
- **Nothing else** — the GLiNER int8 model (196,778,982 bytes) and the
  DeBERTa-v3 tokenizer are embedded in the exe: single file, no install, no
  network, CPU only. The exe imports just `KERNEL32.dll` + `msvcrt.dll`.

## Build

`build.sh` (x86_64, MinGW) and `build_arm64.sh` (WoA, llvm-mingw). Both run
the static-analysis gate
(`bugprone/cert/misc/clang-analyzer/concurrency/portability/performance`
clang-tidy set, zero user-code warnings) and a **fatal** `clang-format
--dry-run --Werror` gate over the hand-written sources. The repo-root
`build.sh` builds this project with the others.

Runtime layout: just `dist/piirate.exe`. Nothing to deploy beside it; the
inbox `onnxruntime.dll` is provided by Windows 11 (24H2+). If the box lacks it
the exe exits 4 with a clear message.

## Layout

```
piirate.c            scanner + GLiNER preprocessing + ORT calls + decode + CLI
pii_tok.c            tokenizer port (Strip -> NFKC charsmap -> space collapse
                     -> Metaspace ▁ -> Unigram Viterbi, fuse_unk, unk=3)
include/pii_tok.h        tokenizer API + token-id constants
include/tok_data.h       GENERATED: 128,000-piece vocab (blob+offsets+scores)
                         + NFKC precompiled_charsmap bytes
include/tok_ranges.h     GENERATED: exact Unicode \w range table (the GLiNER
                         whitespace splitter's regex)
include/piirate_model.h  GENERATED index: part table, PII_MODEL_SIZE, SHA-256
include/pii_model_partNN.h GENERATED: the 196,778,982 raw model bytes, 12 parts,
                         C string literals (raw-bytes-in-source requirement;
                         parts stay under git's 100 MB/file ceiling)
include/onnxruntime_*.h  Microsoft ONNX Runtime 1.29 C API declarations (MIT)
                         — declaration-only; nothing is linked at build time
tools/               gen_tok_data.py, gen_model_blob.py (the generators; run
                     from the project root with tokenizer.json / model.onnx in
                     cwd — they write include/),
                     tokenizer.json / tokenizer_config.json / gliner_config.json
                     (upstream sources), gt_tok_fixture.txt + test_tok.c
                     (host-side tokenizer regression bench: 124/124 byte-exact
                     against the HF reference tokenizer:
                     gcc -std=c89 -Wall -Wextra -Werror -O2 -I. \
                         pii_tok.c tools/test_tok.c -o /tmp/test_tok &&
                     /tmp/test_tok < tools/gt_tok_fixture.txt )
```

`model.onnx` itself is not stored next to the parts (it exceeds git's 100 MB
file cap); the ORT C API declarations come from Microsoft's MIT-licensed
ONNX Runtime 1.29 headers (`include/onnxruntime_c_api.h` +
`onnxruntime_error_code.h` + the two `onnxruntime_ep_*`/float16 headers they
pull — declaration-only; the table layout is append-only, so calls available
in API ≤ 17 work against the 1.29 declaration set). To regenerate the parts
or verify the embedded bytes:

```
curl -LO https://huggingface.co/blinkwrite-ai/gliner-small-pii-onnx-int8/resolve/main/model.onnx
sha256sum model.onnx   # = 2ac41b218b8a87aaf06222fe6431e04b7b2cccb1acc41d1009696ce455014ef7
python3 tools/gen_model_blob.py   # run from the project root with model.onnx in cwd
python3 tools/gen_tok_data.py     # run from the project root with tokenizer.json in cwd
```

## How it works (abstraction level)

1. **Files** are walked with `FindFirst/NextFileW` (recursion depth-capped,
   reparse points skipped), read up to `--max-file-mb` (default 4 MiB). A
   UTF-16LE BOM is transcoded to UTF-8; a UTF-8 BOM is stripped; other bytes
   pass through.
2. **Words** are GLiNER's splitter: regex `\w+(?:[-_]\w+)*|\S` with the exact
   Unicode `\w` semantics (generated range table). Words > 1024 bytes are
   truncated.
3. **Prompt**: per label the words `<<ENT>>` + `<label>`; then `<<SEP>>` —
   identical to GLiNER's `SpanProcessor.prepare_inputs` (markerV0 mode).
4. **Tokenization** per word = HuggingFace pipeline from the shipped
   `tokenizer.json`: Strip → NFKC via the SPM `precompiled_charsmap`
   double-array trie (byte-exact bit ops) → collapse space runs → Metaspace
   (`\x20` → `▁`, prepend, split) → Unigram Viterbi (`min_score − 10` unk
   penalty, `fuse_unk`, no byte fallback). Parity is enforced by
   `tools/test_tok.c` + `gt_tok_fixture.txt` (124 cases, byte-exact ids,
   incl. fullwidth/fraction/circled-NFKC edge cases).
5. **Sequence**: `[CLS]` …ids… `[SEP]`; `attention_mask` all 1;
   `words_mask` marks the first subtoken of each text word (1-indexed, prompt
   skipped) per `subtoken_pooling="first"`; `text_lengths = [n_words]`;
   `span_idx` = all `(i, i+j)`, `j<12`; `span_mask = (i+j < n_words)`
   (int64 per this build's patched `span_mask_int64` input).
6. **Inference**: `LoadLibraryW("onnxruntime.dll")` → `OrtGetApiBase()` →
   `GetApi(17)` (the inbox runtime's ceiling) → `CreateSessionFromArray` on
   the embedded bytes → six int64 tensors → `Run` → `logits`
   `[1, words, 12, labels]` float32.
7. **Decode** = GLiNER flat span decode: `sigmoid > threshold`, valid spans
   `start + width-index + 1 <= n_words`, then score-descending greedy
   non-overlap (stable: first-seen wins ties), output sorted by position.
8. Windows are word-runs bounded by the 512-token DeBERTa sequence cap
   (`2 + prompt + text pieces ≤ 512`), overlapping 32 words; cross-window
   duplicates are removed by (char-range, label).

The result reproduces the Python reference pipeline (GLiNER library semantics
with `tokenizers` + `onnxruntime`) bit-for-bit on the regression corpus —
same spans, same labels, same scores to 4 decimals.

## Notes / limitations

- NER is best-effort: the model's own README warns recall is not 100% and the
  0.2 threshold trades precision for recall. This tool surfaces findings; it
  is not a redaction control.
- English prose is the tuned register (per the model card).
- INT8 dynamic quantization costs some accuracy vs the fp32 base model.
- Model attribution: Apache-2.0; base `vicgalle/gliner-small-pii`; encoder
  `microsoft/deberta-v3-small`; GLiNER (Zaratiana et al., 2023).
