# ocular-rip

**ocular-rip.exe** — rip text out of images using Windows' own OCR engine.

> **Code-flow diagram:** `flow.html` — full mermaid flowchart of the binary,
> derived 1:1 from the current source (open in a browser; renders via the mermaid CDN).

A standalone CLI: image → text via the inbox `Windows.Media.Ocr` WinRT API
(the engine that ships inbox since Windows 10 1607). Pure C89, calls
the WinRT COM ABI directly — no C++/WinRT, no cppwinrt, no third-party
libraries, no bundled DLLs.

## Usage

```
ocular-rip.exe [--verbose|-v] <input_image> [output_txt]
```

OCRs the input image with the inbox `Windows.Media.Ocr` engine and writes
the recognized text (UTF-8) to `<output_txt>` — **or to stdout when no output
path is given**. Progress goes to stderr (`Input:` / `Output:` /
`OCR succeeded: N byte(s)`); the recognized text itself goes only to the
output file or stdout, never both.

```
ocular-rip.exe C:\scan\page1.png C:\scan\page1.txt
type C:\scan\page1.txt
ocular-rip.exe shot.png              # recognized text on stdout instead
ocular-rip.exe --verbose shot.png    # + per-stage tracing to stderr
```

`--verbose`/`-v` prints stage-level tracing to stderr: every factory
activation HRESULT, each async stage (`FileRandomAccessStream.OpenAsync`,
`BitmapDecoder.CreateAsync`, `GetFrameAsync`, `GetSoftwareBitmapAsync`,
`OcrEngine.RecognizeAsync`), the delegate's `QueryInterface`/`Invoke` calls,
and — if a wait times out — the op's own `IAsyncInfo` status and error
code, which tells a wedged op (`Started`, 0x80070102 = WAIT_TIMEOUT) apart
from a failed one (`Error`, real HRESULT).

Exit codes: `0` success · `1` usage · `4` OCR failed (full HRESULT printed) ·
`5` output file could not be opened or written.

### Requirements

- **Windows 10 1607+** — the WinRT OCR engine is inbox on every edition; no
  Windows App SDK, no package identity, no capability declarations, no
  third-party DLLs.
- **An OCR-capable language pack for one of the user's profile languages.**
  The engine is created with `OcrEngine.TryCreateFromUserProfileLanguages()`,
  so if none of the user's installed languages carries OCR support the run
  fails. Check what the box has:
  `powershell -NoProfile -Command "[Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]|Out-Null; [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages"`
  and add more via Settings → Time & language → Language & region → Add a
  language → tick its *Optical character recognition* option.
- **A decodable image** — any format the built-in `BitmapDecoder` supports
  (PNG, JPEG, BMP, GIF, TIFF), at most `OcrEngine.MaxImageDimension` pixels on
  a side (query it the same way; 10000 measured on a Win11 26200 box).
- **CPU only, offline** — no GPU/NPU, no network. The binary writes nothing
  to disk except the output text file you name.

## Build

`build.sh` (x86_64) and `build_arm64.sh` (WoA aarch64, llvm-mingw) — both
static C runtime, `-Wall -Wextra -Werror`. Outputs land in `dist/`.
The repo-root `build.sh` builds this project along with the others.
