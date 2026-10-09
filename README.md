# LOLAI - WWHF 2026

This repo containts the code for my talk `LOLBins? What about LOLAI?` at WWHF 2026. The repo consists of several stand-alone projects that leverage on-device AI/ML capability organic to Windows. The implementations contained in this repo are intended as proof-of-concept implementations only, and not as production code. Some might notice I didn't bother to implement these in a post-exploitation format. That's on purpose.

Due to personal preference the C code is written to the C89 standard, and the code calls the WinRT COM ABI directly. I chose this for a few reasons, the first is that I prefer the syntax of older C standards, but additionally by avoiding the use of the C++/WinRT SDK this implementation can be used as reference to implement these same capabilities in any language without too much trouble. As part of the validation of this, the code in and build scripts in this repository are intended to be built on Linux systems, instead of Windows. 

The code in this repository, and the README.md's for each project were written with a lot of LLM assitance (shoutout to GLM 5.2 and 5.3). I took the time to manually rewrite some of *this* README.md by hand to ensure that my research and methodology could be understood without having to pipe this into an LLM.


## Build everything
`sh build.sh` → binaries land in `dist/`.

## Build only the project you want
`<project directory>/build.sh` or `<project directory>/build_arm64.sh`.

The individual project README.md files are LLM generated but conatain enough information to get your started using the primitives used by the examples.

**NOTE**: The arm64/aarch64 builds were not rigoursly tested on WoA systems, so there's likely to be a few kinks there.

---


## 1. The AI/ML surface 

### 1.1 WinRT APIs (`Windows.*` namespaces)

Metadata lives in `C:\Windows\System32\WinMetadata\*.winmd`. The `.winmd` extension is a binary format that contains information about namespaces and interfaces. As part of the development for the binaries in this project, LLMs were used to parse through these files and identify relevant information for the implementation. Through this process, I was able to identify a few classes that are registed globally on Windows 11 25H2 that can be used in a stand-alone unpackaged `.exe`.

| Class | Namespace doc | Used by |
|---|---|---|
| `Windows.Media.Ocr.OcrEngine` | image → text (OCR), Windows 10 1607+ | `ocular-rip.exe` |
| desktop **SAPI5** (`SpInprocRecognizer` + dictation) | speech → text | `parrot-rip.exe` |

Both were tested successfully on x64 Windows 11 25H2.

### 1.2 Other Windows AI/ML surfaces

Windows also ships `Microsoft.Windows.AI.*` APIs via the **Windows App SDK**
(Phi Silica `LanguageModel`, NPU `TextRecognizer`, `ImageDescriptionGenerator`,
`ImageScaler`, `ImageGenerator`, `SpeechRecognitionModel`,
`Windows ML`, Windows Studio Effects, Recall / Click to Do / Semantic
Search). I forced my research workflow to try to use these APIs but there's several limitations. Unlike the previously mentioned interfaces, these are **framework-package classes** that require
the App SDK framework in the caller's package graph (bootstrapper
`MddBootstrapInitialize`), MSIX identity + the restricted `systemAIModels`
capability, and — for Phi Silica — a **Limited Access Feature (LAF)** token
from Microsoft. 

This means every unpackaged route to them is gated (§5). No binary here
calls them, but they're mentioned here for completeness. §5 maps the capability/requirement matrix
empirically.

This repo's live binaries all operate at the **inbox OS level** (one operates
above the cloud: `silent_copilot` rides M365 Copilot's own SignalR channel).

---

## 2. Project map

| Project | Binary | What it does | AI/ML surface used | Status |
|---|---|---|---|---|
| `ocular-rip/` | `ocular-rip.exe` | image file → UTF-8 text | **inbox `Windows.Media.Ocr.OcrEngine`** (CPU, WinRT) | shipped, verified on Windows |
| `parrot-rip/` | `parrot-rip.exe` | one utterance from default mic → UTF-8 text | **inbox desktop SAPI5** (`SpInprocRecognizer`, dictation, offline) | shipped, verified end-to-end on the target box |
| `silent_copilot/` | `silent_copilot.exe` | CLI prompt → full M365 Copilot reply on stdout, invisible to the logged-in user | **M365 Copilot cloud LLM over its live SignalR/Chathub WebSocket**, session credentials harvested from process memory | shipped, verified incl. across reboot |
| `piirate/` | `piirate.exe` | recursive directory → PII findings on stdout | **embedded GLiNER int8 ONNX model** (PII NER) on the **inbox `System32/onnxruntime.dll`** (OrtApi v17) via the C ABI + a from-scratch C89 port of the HF tokenizers pipeline | shipped, verified on the target box (recursion, UTF-16, multi-window, determinism, controls) |

Each live project also ships an LLM-generated mermaid code-flow diagram: `ocular-rip/flow.html`,
`parrot-rip/flow.html`, `silent_copilot/flow.html`, `piirate/flow.html`.

---

## 3. WinRT from C89

The techniques below let you reproduce the WinRT binaries here (ocular-rip);
parrot-rip (§4.2) uses plain COM events instead, and silent_copilot
(§4.3)/piirate (§4.4) use plain COM + socket/loader.

### 3.1 C-interface COM vtables 

We use the `COBJMACROS` with `#define COBJMACROS 1` / `CINTERFACE 1` where SDK COM is used
to specify that we will be using COM interface methods in pure C. WinRT objects are consumed via
hand-declared vtable structs. The base vtable layout for every WinRT interface
in this repo is `IUnkVtbl`: `QueryInterface`,
`AddRef`, `Release`, then three `IInspectable` slots (`GetIids`,
`GetRuntimeClassName`, `GetTrustLevel`). 

Each interface's own methods start at
**absolute vtable slot 6**; inheritance inserts parent methods in-between, so
slot math is done per-interface from the winmd's `MethodList` order (see
`ocular-rip/winrt_ocr.h:76-159` for examples with `/* slot */`
annotations).

### 3.2 Activation

- Factory (statics) classes: `RoGetActivationFactory(HSTRING className, IID, out)`,
  wrapped by `get_factory`.
- Apartment: `RoInitialize(RO_INIT_MULTITHREADED)` — MTA — with
  `RPC_E_CHANGED_MODE` tolerated. For
  silent_copilot/piirate the same tolerance exists on their COM init paths.
- Runtime-class name strings are passed as `HSTRING` created with
  `WindowsCreateString`.

### 3.3 The async ABI

Every WinRT `*Async` method returns in its out-param a pointer that **is already
the instantiation interface** (`IAsyncOperation<T>` or
`IAsyncOperationWithProgress<T,P>`) — **no `QueryInterface` for a per-`T` IID is
required or performed** (per-`T` IIDs are computed by the WinRT generic-GUID
algorithm and are absent from `.winmd`).
The vtable layout, extracted from `Windows.Foundation.winmd`:

```
slots 0-2   IUnknown
slots 3-5   IInspectable
slots 6-10  IAsyncInfo        (get_Id, get_Status, get_ErrorCode, Cancel, Close)
IAsyncOperation<T>:
  slot 11   put_Completed(handler)
  slot 13   GetResults() -> T
IAsyncOperationWithProgress<T,P>:
  slot 13   put_Completed(handler)
  slot 15   GetResults() -> T
```

This part is a little bit of a mess, but it's interesting to look at how GLM put this thing together. The gist is that we manually declare a vtable that's populated with the COM methods that we need, query for the interface based on the IID, and then use the IAgileObject so the completion callback can run on the background thread without cross-thread marshaling. This is basically a way of invoking COM things without actually following COM design patterns. If you need to know more, read on. Otherwise, skip to the next section. 

A single generic driver, async_wait(op, completed_slot, results_slot, &result), drives both interfaces:

 - The Completed callback is a hand-written WinRT delegate whose vtable is just IUnknown followed by Invoke at slot 3
When the operation finishes, the runtime calls Invoke, which records the AsyncStatus and signals an auto-reset event
async_wait then blocks on that event, up to the operation's 60-second timeout, and requires the
   status to be Completed (value 1).

 - Before calling put_Completed, the runtime asks the delegate for its interface via QueryInterface. Our handler answers IUnknown,
   IInspectable, and IAgileObject, and — crucially — grabs the first unknown IID the runtime requests (the typed AsyncOperationCompletedHandler<T>) and stores it
   in g_handler_iid.

 - The handler declares itself IAgileObject ({94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90}). This is what lets the completion
   fire on the MTA-hosted background thread and call back into our code without any COM cross-thread marshaling.

 Once signaled, async_wait calls GetResults at the appropriate slot to fetch the typed result.

### 3.4 Strings out, text out

Results come back as `HSTRING` (UTF-16). Read with
`WindowsGetStringRawBuffer`, converted to UTF-8 with two-pass
`WideCharToMultiByte(CP_UTF8,…)`.

---

## 4. Project deep dives

### 4.1 `ocular-rip` — image → text via inbox OCR

**API:** `Windows.Media.Ocr.OcrEngine` — runs on CPU; requires no App SDK, no identity,
no LAF.

**Pipeline** (all single-threaded MTA; every `*Async` awaited with slots
11/13; line refs to `ocular-rip/ocular-rip.c`):

| Step | Activation / call | IID (header `ocular-rip/winrt_ocr.h`) | Vtable slot | Code |
|---|---|---|---|---|
| 1 | `RoGetActivationFactory("Windows.Storage.Streams.FileRandomAccessStream")` → `OpenAsync(path, Read)` | `IID_IFileRandomAccessStreamStatics` `73550107-…` | `OpenAsync` = **6** | :248, await :250 |
| 2 | `RoGetActivationFactory("Windows.Graphics.Imaging.BitmapDecoder")` → `CreateAsync(stream)` | `438CCB26-…` | `CreateAsync` = **14** — preceded by 8 decoder-ID getters | :266-273 |
| 3 | `decoder.GetFrameAsync(0)` → QI `IBitmapFrameWithSoftwareBitmap` | `FE287C9A-…` (`:40`) | `GetFrameAsync` = **10** | :283-289 |
| 4 | `frame.GetSoftwareBitmapAsync()` | — | **6** | :300-303 |
| 5 | `RoGetActivationFactory("Windows.Media.Ocr.OcrEngine")` → `TryCreateFromUserProfileLanguages()` (synchronous) | statics `5BFFA85A-3384-3540-9940-699120D428A8`; engine `5A14BC41-…`| `TryCreateFromUserProfileLanguages` = **10** | :316-321 |
| 6 | `engine.RecognizeAsync(softwareBitmap)` → `OcrResult` | result `9BD235B2-…`| `RecognizeAsync` = **6**  | :328-331 |
| 7 | `result.get_Text()` → HSTRING → UTF-8 file | — | `get_Text` = **8** | :345-355 |

Notes:
- The statics factory exposes `get_MaxImageDimension` — the
  engine will reject oversized images; but we pass the bitmap straight through without validating anything.
- OCR language = *user profile languages* (step 5); an OCR language pack must
  be installed (header comment).
- Exit codes: `0` ok · `1` usage · `4` OCR/HRESULT error · `5` output-file
  error.
- Build: MinGW `-std=c89 -Wall -Wextra -Werror -municode -O2 -static -lole32
  -luuid -lruntimeobject` (`ocular-rip/build.sh`); ARM64 via
  `ocular-rip/build_arm64.sh` (llvm-mingw `aarch64-w64-mingw32-gcc`).

### 4.2 `parrot-rip` — voice → text via the desktop SAPI5 engine

This is probably the hackiest example — and the least reliable. SAPI5's recognition is fast but blunt, so even after trimming I still get errors. Treat it as a proof-of-concept, not something to build on.

**Engine:** an in-process `SpInprocRecognizer` (CLSID `41B89B6B-9399-11d2-9623-00C04F8EE628`) over the SAPI5 stack shipped with Windows since Vista. It runs fully offline — no WinRT async, no privacy gate, no third-party code — and links only OS import libraries (`ole32`, `oleaut32`, `user32`, `winmm`, `msvcrt`).

**Pipeline**

1. **Capture** — MME `waveInOpen` on `WAVE_MAPPER` at 16 kHz / 16-bit mono with 8 recycled 32 000-byte headers; a 60 s window is recorded into a growable heap buffer. Per-buffer peak tracking bails early on pure silence, and `trim_silence` then keeps only the speech plus a 1 s pad on each side.
2. **Engine** — the raw PCM (no WAV header; `GetFormat` already declares 16 kHz PCM) is wrapped in a hand-written `IStream` / `ISpStreamFormat` COM object. Of its 15 vtable slots, `Read`, `Seek`, `Stat`, and `GetFormat` are real; `Write`, `SetSize`, and `Clone` return stub errors, and `Read` returns `S_FALSE` at end of stream.
3. **Init** — `CoInitializeEx(MTA)` → `CoCreateInstance(SpInprocRecognizer)` → `CreateRecoContext` → QI `ISpEventSource`.
4. **Events** — `SetNotifyWin32Event()` takes no parameters: SAPI owns its own Win32 event and sets it whenever events are queued. parrot-rip calls that slot, grabs the handle with `GetNotifyEventHandle()`, and waits on it with a deadline. The blocking slot (`WaitForNotifyEvent`) is deliberately unused.
5. **Grammar** — `SetInput(stream, FALSE)` (the format is fixed by `GetFormat`) → `CreateGrammar` → `LoadDictation` → `SetDictationState(SPRS_ACTIVE)`.
6. **Loop** — `WaitForSingleObject` on the event in ≤250 ms hops up to a 60 s deadline. `SPEI_RECOGNITION` events hand back an `ISpRecoResult`; `GetText` pulls the result to UTF-8 and frees the buffer; `SPEI_END_SR_STREAM` marks the buffer done.
7. **Ownership** — the stream object owns the PCM buffer and frees it on `Release`, so callers must not free it themselves.

### 4.3 `silent_copilot` — CLI → M365 Copilot reply with zero footprint

A cloud-AI channel hijack: it pulls the desktop app's own authenticated WebSocket session out of live process memory and reuses it, sending the reply to stdout only. The reasoning comes from Microsoft's hosted Copilot behind `substrate.office.com` (M365 Substrate). Four layers:

#### Layer 1 — session-artifact harvesting from process memory

- **Enumerate** every PID with `CreateToolhelp32Snapshot`, matching by name. `m365copilot.exe` and its `msedgewebview2.exe` children are scanned first, then every other readable process.
- **Read** carefully: a `VirtualQueryEx` walk inspects only committed, readable, non-guard pages, taking 256 KiB chunks with a 128-byte overlap so artifacts straddling a read still match.
- **Match** four artifacts in each window:
  - **tokens** — base64url strings starting with `eyJhbGciOiJkaXIi` (`{"alg":"dir"…`, a direct-encryption JWE), ≥ 200 chars: the app's live `access_token`s.
  - **STEN** — a 36-char GUID whose last 12 hex digits are all `a`: the tenant/session id.
  - **OID** — a v1 GUID (`00000000-0000-1…`), optional, only used in the pass-2 URL.
  - **variants** — a string beginning `EnableMcpServerWidgets`: an A/B flag echoed into the URL.

#### Layer 2 — replaying the Chathub session (`try_token`)

Each harvested token is tried twice — the second pass adds an `oid@` prefix and the variants blob — then the following sequence runs:

1. **TLS** — connect to `substrate.office.com:443` over Windows' inbox **Schannel (SSPI)**, chain-validated against the Windows trust store.
2. **WebSocket handshake** — `GET /m365Copilot/Chathub/…`, passing the session/request IDs and `access_token` as query params (`source="officedesktop"`, …). Requires a `101` response.
3. **SignalR handshake** — send exactly 32 bytes, `{"protocol":"json","version":1}\x1e`, where `\x1e` is the frame delimiter.
4. **Invoke** — a single `type:4` streaming-invocation frame carrying the prompt. Every ID is fresh per attempt (a new client-generated `ConversationId` GUID), so the substrate stands up the conversation on demand and no token↔conversation pairing is ever needed.
5. **Receive** — split frames on `\x1e` and parse the message `type`:
   - `1` (stream item) → extract the assistant text from the scoped `messages[]` array at its own element depth, so nested follow-ups can't be mistaken for the reply.
   - `2/3` (completion) → take `result.message` verbatim as the final text.
   - JSON strings are decoded through `\uXXXX` escapes, including UTF-16 surrogate pairs, into UTF-8.
6. **Reply → stdout. Only.**

#### Layer 3 — hidden UI

- **No console** — built with `-mwindows`, so the parent terminal never flashes. stdout/stderr go through raw `WriteFile` on handles captured *before* `AttachConsole`, so piped output survives from any calling context. By default it writes nothing to disk; `--trace` adds WS-frame dumps to stderr and a `silent_copilot_dbg.log` next to the exe.
- **Launch hidden** — if Copilot isn't running, it's launched invisibly into the target user's interactive session, via one of two paths depending on where it runs:
  - **Interactive fast path** (the exe is already in the user's active console session, e.g. a PowerShell prompt): activate the app in-process and hide its windows on a worker thread — no services, no borrowed tokens, ~2 s.
  - **Foreign-session path** (an SSH/service session): `launch_in_session` either borrows a token from an existing user process and launches it with `CreateProcessWithTokenW --launch-hide`, or — as a fallback — registers a Task Scheduler entry with the interactive logon type so it runs hidden in the session, then removes the task on completion.
- **The hide driver** activates the packaged app (AUMID `Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe!Microsoft.MicrosoftOfficeHub`) through the out-of-process `IApplicationActivationManager` with two WinEvent hooks that `ShowWindow(SW_HIDE)` the instant any new window appears, plus a 90 s `EnumWindows` brute-force backstop. Verified: zero visible windows after launch.

#### Layer 4 — orchestration (`main`)

1. Dispatch `--launch-hide`.
2. `ensure_session_material` — poll up to 25 times: if the app isn't running, grab our own active interactive session (via WTS), launch it hidden, and rescan until a token and STEN exist. The task-scheduler artifact is deleted on success.
3. Try each token over the Chathub channel — 30 s per token, 420 s global — until a reply arrives or the deadline hits.
4. Exit 0 only when a reply was captured. Everything is dynamic: because nothing is persisted or hardcoded beyond protocol constants, it survives reboots, app reinstalls, and profile changes.

### 4.4 `piirate` — directory → PII via an embedded GLiNER ONNX model

**Model:** `blinkwrite-ai/gliner-small-pii-onnx-int8` — a GLiNER span-level NER model with a DeBERTa-v3-small encoder (Apache-2.0). All 196,778,982 weight bytes are embedded directly in C source: split into 12 parts (`piirate/include/pii_model_partNN.h`) to stay under git's 100 MB per-file ceiling, stored as `\xNN` string literals, with the SHA-256 (`2ac41b218b8a87aaf06222fe6431e04b7b2cccb1acc41d1009696ce455014ef7`) printed in `piirate/include/piirate_model.h` for verification.

**Runtime** is the default Windows ONNX Runtime — `LoadLibraryW(L"onnxruntime.dll")` + `OrtGetApiBase()` + `GetApi(17)`. Measured against System32 on my Win11 25H2 lab box, it's ORT 1.17.1, API 1–17; every call predates v17, so the 1.29 MIT declaration headers under `piirate/include/` stay ABI-compatible.

**Pipeline**

1. **Walk** — `scan_dir` does a depth-capped recursive `FindFirstFileW` walk and never follows reparse points.
2. **Decode** — `read_file_utf8` normalizes each file to UTF-8, detecting a UTF-8 or UTF-16LE BOM, and for BOM-less files falling back to a NUL-density heuristic to guess UTF-16LE.
3. **Split** — GLiNER's word splitter applies `\w+(?:[-_]\w+)*|\S` using a generated table of exact Unicode `\w` code-point ranges.
4. **Prompt** — the labeled entities are formatted as `<<ENT>> <label>… <<SEP>>`.
5. **Tokenize** — a byte-exact port of HF's `tokenizers` chain: Strip → SentencePiece (with a `precompiled_charsmap` whose double-array trie and bit-ops are ported from upstream SPM) → Metaspace → Unigram Viterbi (`unk = min_score − 10`, `fuse_unk`, no byte fallback). A parity bench confirmed 124/124 byte-identical token IDs against the reference.
6. **Feed** — six int64 tensors into the model: `input_ids`, `attention_mask`, `words_mask`, `text_lengths`, `span_idx`, and `span_mask_int64` (the BOOL→INT64 patch for this build).
7. **Run & decode** — `Run` produces logits `[1, words, 12, labels]`, which the GLiNER flat decoder turns into spans (sigmoid > 0.2, a valid-span rule, greedy non-overlap by descending score). Each finding prints as `path -> label (score): "span"`.

For the DeBERTa encoder, Windows stays under the 512-token limit by processing text in 32-word-overlapping windows, then deduping spans that repeat across window boundaries.

---

## 5. Capability matrix

| Surface | App SDK needed | Package identity | Restricted capability | Microsoft-issued approval | HW accel |
|---|---|---|---|---|---|
| `Windows.Media.Ocr` (ocular-rip) | No | No | No | No | CPU |
| desktop SAPI5 dictation (parrot-rip) | No | No | No | No | CPU, offline-capable |
| M365 Copilot Chathub (silent_copilot) | No — inbox Schannel TLS + hand-rolled WS | No | No | uses the app's own live session | cloud |
| `Microsoft.Windows.AI.Text.LanguageModel` (Phi Silica) | Yes (bootstrapper) | MSIX required | `systemAIModels` | **LAF token** | NPU/GPU on Copilot+ |
| `Microsoft.Windows.Private.Workloads.SessionManager` (internal broker) | Yes | MSIX required | `Microsoft.coreAppActivation` custom capability (first-party-only) | Microsoft-granted | NPU |
| `Windows.AI.Actions` runtime | inbox (`Windows.AI.Agents.dll`) | Yes + AI-Actions host registration | — | — | service-dependent |
| inbox ONNX Runtime (piirate) | No — `System32/onnxruntime.dll`, `LoadLibrary` at run time | No | No | No | CPU (inbox ORT 1.17.x on Win11) |

Gate HRESULTs observed at runtime on real hardware (both x64 and WoA ARM64),
with what each one tells you:

| HRESULT | Meaning |
|---|---|
| `0x80040154` | The CLSID isn't in this process's package graph, so it can't be activated. |
| `0x80080005` | The class resolves, but the out-of-process launch was refused because the caller has no package identity. |
| `0x80070005` | A restricted capability was declared but the app is unsigned (or it was denied). |
| `0x80004021` | Requires AI-Actions host registration. |

The AI activation readiness check (`GetReadyState()`) returns one of:

| Value | State |
|---|---|
| `0` | Ready |
| `1` | NotReady |
| `2` | NotSupportedOnCurrentSystem |
| `3` | DisabledByUser |
| `4` | CapabilityMissing |
| `5` | NotCompatibleWithSystemHardware |
| `6` | OSUpdateNeeded |

---

## 6. Building

Prereqs: `x86_64-w64-mingw32-gcc` (x64), llvm-mingw `aarch64-w64-mingw32-gcc`
(ARM64), both ≥13-compatible. Strict flags everywhere:
`-std=c89 -Wall -Wextra -Werror`; static CRT (`-static`) → imports are OS-only.

```sh
sh build.sh          # all live projects, x64 (+ arm64 where scripted) -> dist/
```

Per-project: `ocular-rip/build.sh` & `build_arm64.sh`,
`parrot-rip/build.sh` & `build_arm64.sh`, `silent_copilot/build.sh`.

### Dockerized build

```sh
sh docker_build.sh                 # build all binaries via Docker
sh docker_build.sh --rebuild-image # force a toolchain-image rebuild
```

`docker_build.sh` builds (and caches) a reproducible toolchain image pinned
to the exact toolchains I used, then runs the normal `build.sh` inside the
container with the repo bind-mounted at its real host path:

- **x64:** mingw-w64 GCC `13.2.0-6ubuntu1+26.1` (ubuntu:24.04 / noble universe)
- **arm64:** llvm-mingw `20260826` — LLVM 23.1.0 final, commit
  `ea7d852a70e8bdfaf601d6626a760f9771b2c4b4`, tarball sha256
  `cee8d2ce3da5145ce4dc882e70d0b0719a783d53a99752c60948fc0659975a65`

The image build verifies the tarball sha256 and the exact llvm-project commit
**before** the toolchain is used, so the toolchain can't drift. Binaries land
in `./dist`, owned by the invoking user, and are **byte-identical to local
builds on both architectures**.

Static analysis + formatting:
- **clang-tidy gate** at the end of every x64 `build.sh` (`llvm-mingw`, `--target=x86_64-w64-windows-gnu`): `bugprone`, `cert`, `misc` (minus `misc-include-cleaner`, which misfires on the `windows.h` umbrella), `clang-analyzer`, `concurrency`, `portability`, `performance`. **Zero warnings** across all three sources.
- Formatting via the repo-root **`.clang-format`** (LLVM base, 4-space indent, 100 cols, `SortIncludes: Never` so `windows.h` stays first). Run `clang-format -i <file>` from `~/llvm-mingw/bin`.

---

## 7. External references

- [Phi Silica / Windows AI APIs](https://learn.microsoft.com/en-us/windows/ai/apis/) (+ `/phi-silica`)
- [`Windows.Media.Ocr`](https://learn.microsoft.com/en-us/uwp/api/windows.media.ocr.ocrengine)
- [SAPI5 (desktop speech)](<https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee125663(v=vs.85)>)
- [Limited Access Features](https://learn.microsoft.com/en-us/uwp/api/windows.applicationmodel.limitedaccessfeatures) · [request form](https://go.microsoft.com/fwlink/?linkid=2271232)
- [Windows App SDK bootstrapper/Dynamic Dependency sources](https://github.com/microsoft/WindowsAppSDK)
- Windows AI component servicing: Microsoft Support KB family for Phi Silica / Image Processing / Image Transform components
- **GLiNER PII model**: [`blinkwrite-ai/gliner-small-pii-onnx-int8`](https://huggingface.co/blinkwrite-ai/gliner-small-pii-onnx-int8) (base GLiNER: [github.com/airbnb/gliner](https://github.com/airbnb/gliner))
- **Tokenizer reference**: HF [`tokenizers`](https://github.com/huggingface/tokenizers) (0.23). The `piirate` word-level chain (SPM double-array trie → Metaspace → Unigram Viterbi) is a byte-exact C89 port of this.
- **Runtime**: [ONNX Runtime](https://github.com/onnx/runtime) (`OrtApi` v17, loaded from `System32/onnxruntime.dll`)
