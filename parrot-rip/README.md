# parrot-rip

**parrot-rip.exe** — it hears you, it repeats you: rip text out of speech.

A standalone CLI: voice → text using Windows' **desktop SAPI5 speech engine**
(in-proc `SpInprocRecognizer` + dictation grammar — inbox since Windows Vista).
Pure C89, plain MinGW COM, no third-party libraries, no WinRT, no network, no
privacy gate. Works on hosts where the newer `Windows.Media.SpeechRecognition`
runtime is unavailable.

> **Code-flow diagram:** `flow.html` — mermaid flowchart of the binary,
> derived 1:1 from the current source (mermaid CDN renders it).

## Usage

```
parrot-rip.exe [--verbose|-v] [--timeout N] [out.txt]
```

Records a listen window from the default microphone (default 60 s; `--timeout N`
sets it to N seconds, 1–86400), trims the silence around the speech, and runs
it through the inbox desktop SAPI5 dictation engine. The recognized text
prints to **stdout** as UTF-8 (and to `out.txt` when given).

```
parrot-rip.exe                        # speak during the 60 s window; text on stdout
parrot-rip.exe --timeout 10           # 10 s listen window instead
parrot-rip.exe --verbose              # + capture/trim stats and every SR event id on stderr
parrot-rip.exe note.txt               # also write the text to note.txt
```

`--verbose`/`-v` prints stage-level tracing (capture byte count and peak,
trim bounds, engine bring-up HRESULTs and every SR event id) to stderr. A
fully silent window ends with `no speech captured before the listen window
elapsed` (exit 1). Offline — no online-speech privacy consent is needed.
The `--timeout` flag bounds the listening period only; the engine-processing
deadline after capture is at least 30 s regardless, so short windows do not
cut recognition short.
Exit codes: `0` utterance transcribed · `1` usage / engine / no speech ·
`5` out-file error.

### Requirements

- **Windows Vista+** — the desktop SAPI5 speech stack is inbox (classic COM
  SAPI, not the gated `Windows.Media.SpeechRecognition` runtime).
- **An active default microphone** — capture goes through the MME `waveIn`
  API at 16 kHz / 16-bit / mono from the default capture device.
- **A dictation-capable desktop SR engine** — en-US boxes ship the
  `MS-1033-80-DESK` token (`SR Engine 8.0`, data under
  `C:\Windows\Speech\Engines\SR\en-US\`). No download required; it is
  the only recognizer exposed to unpackaged callers.
- **Microphone access enabled for desktop apps** — Settings → Privacy &
  security → Microphone: *Microphone access* On and *Let desktop apps
  access your microphone* On. On Win11 the desktop-app grant lives at
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged`
  (`Value`=`Allow`).
- **Accuracy expectations** — the installed dictation engine is the
  Vista-era HMM acoustic model. Clear, deliberate dictation of longer
  phrases recognizes well; short conversational words (e.g. "Hello") can be
  mangled. That is the engine's ceiling, not a capture problem (verified:
  "from the other side" transcribes perfectly in the same run that
  mangles the greeting).

## Build

`build.sh` (x86_64) and `build_arm64.sh` (WoA, llvm-mingw) — both static C
runtime, `-Wall -Wextra -Werror`, clang-tidy gate, clang-format gate. Binary
imports: `KERNEL32.dll` + `msvcrt.dll` + `ole32.dll` + `oleaut32.dll` +
`user32.dll` + `winmm.dll` (OS only). The repo-root `build.sh` builds this
project with the others.

## How it works (two halves)

1. **Capture** — MME `waveIn` (legacy wave API, inbox) records the listen
   window (60 s default, `--timeout N` to change) of
   16 kHz / 16-bit / mono PCM from the default input device into a growable
   heap buffer (8 recycled 32 000-byte buffers). Pure silence ⇒ early exit.
   `trim_silence` then keeps only the speech region plus a 1 s pad on each
   side, so the engine never has to wade through dead air.
2. **Engine** — SAPI5 in-proc `SpInprocRecognizer` with a dictation grammar,
   fed the captured PCM as a hand-implemented `ISpStreamFormat` COM object
   (`SetInput`), so the engine never touches the audio device itself. A
   parallel top-level rule in the same grammar carries a ~60-word list of
   frequent English words at weight 100 to bias the engine toward common
   vocabulary.

The split exists because on some Windows 11 hosts the in-proc engine's own
audio start wedges (`SetDictationState(ACTIVE)` returns a SPERR warning and no
SR events ever fire) even though MME capture works. Feeding the audio in
ourselves sidesteps that entirely: the engine processes the buffer and emits
`SPEI_RECOGNITION` + `SPEI_END_SR_STREAM` events, which we turn into UTF-8
text on stdout.

### Event notification (the subtle part)

`ISpNotifySource::SetNotifyWin32Event()` takes **no parameters** — it creates
an internal Win32 event inside SAPI that is set whenever events are queued.
parrot-rip calls slot 7 (no args), then `GetNotifyEventHandle()` (slot 9) to
obtain SAPI's event handle and waits on it with a deadline; slot 8
(`WaitForNotifyEvent`) blocks indefinitely and is not used.

### Stream plumbing

Raw PCM (no WAV header — `GetFormat` already tells the engine 16 kHz PCM) is
wrapped in a 15-method `IStream` + `ISpStreamFormat` vtable object:
`Read`/`Seek`/`Stat`/`GetFormat` are real, `Write`/`SetSize`/`Clone` return
stub errors, `Lock`/`Unlock`/`Commit`/`Revert` are no-ops. `Read` returns
`S_FALSE` at EOF. Ownership of the PCM buffer passes to the stream object
(`Release` frees it) — callers must **not** `free()` it afterwards.

### Engine call sequence

Co-Initialize (MTA) → `CoCreateInstance(CLSID_SpInprocRecognizer)` →
`CreateRecoContext` → QI `ISpEventSource` → `SetNotifyWin32Event()` (slot 7,
no args) + `SetInterest(SPFEI_ALL_SR_EVENTS)` → `SetInput(stream, FALSE)` →
`CreateGrammar` → `LoadDictation(L"", SPLO_STATIC)` →
`SetDictationState(SPRS_ACTIVE)` → `GetNotifyEventHandle()` (slot 9) →
`WaitForSingleObject(sapiEvent, ≤250 ms)` to a 60 s deadline → drain
`GetEvents` → `SPEI_RECOGNITION` with `SPET_LPARAM_IS_OBJECT` carries an
`ISpRecoResult` → `GetText(0, ALL)` → CoTaskMemFree after a UTF-8 copy.
Cleanup: dictation inactive, interfaces released, `CoUninitialize`.

Exit codes: `0` utterance transcribed · `1` engine/usage/no-speech · `5` out
file error.