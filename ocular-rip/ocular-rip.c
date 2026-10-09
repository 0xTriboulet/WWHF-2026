/*
 * ocular-rip.c - Standalone CLI: image -> text via Windows.Media.Ocr (the inbox
 * OCR engine that ships with Windows 10 1607+), pure C89, WinRT COM ABI, with the
 * CORRECT async vtable slots (IAsyncOperation<T>: put_Completed=11, GetResults=13).
 *
 * Usage: ocular-rip.exe [--verbose|-v] <input_image> [output_txt]
 *   (no output path = print recognized text to stdout)
 *
 * Build (MinGW cross, static C runtime):
 *   x86_64-w64-mingw32-gcc -std=c89 -Wall -Wextra -Werror -municode -O2 -static \
 *       ocular-rip.c -o dist/ocular-rip.exe -lole32 -luuid -lruntimeobject
 *
 * Flow (main thread, MTA; each *Async out-param is an IAsyncInfo interface:
 * async_wait QIs it for the per-T IAsyncOperation<T> instantiation IID and
 * uses put_Completed=6 / GetResults=8 on that view — see winrt_ocr.h):
 *   RoGetActivationFactory(FileRandomAccessStream) -> OpenAsync(path)    -> IRandomAccessStream
 *   RoGetActivationFactory(BitmapDecoder)          -> CreateAsync(stream) -> BitmapDecoder
 *   decoder.GetFrameAsync(0)                        -> BitmapFrame (QI
 * IBitmapFrameWithSoftwareBitmap) frame.GetSoftwareBitmapAsync()                 -> SoftwareBitmap
 *   RoGetActivationFactory(OcrEngine)             -> TryCreateFromUserProfileLanguages() ->
 * OcrEngine engine.RecognizeAsync(softwareBitmap)          -> OcrResult result.get_Text() ->
 * HSTRING (UTF-16) -> UTF-8 -> out.txt
 *
 * Inbox OS class: NO Windows App SDK, NO package identity, NO LAF. CPU.
 * Requires Windows 10 1607+; install an OCR language pack if out.txt is empty.
 */
#include <windows.h>
#include <objbase.h>
#include <inspectable.h>
#include <roapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "winrt_ocr.h"

static int g_verbose = 0; /* --verbose/-v: stage-level tracing to stderr */
#define TRACE(...)                                                                                 \
    do {                                                                                           \
        if (g_verbose)                                                                             \
            (void)fwprintf(stderr, __VA_ARGS__);                                                   \
    } while (0)

static const wchar_t CLASS_FileRandomAccessStream[] =
    L"Windows.Storage.Streams.FileRandomAccessStream";
static const wchar_t CLASS_BitmapDecoder[] = L"Windows.Graphics.Imaging.BitmapDecoder";
static const wchar_t CLASS_OcrEngine[] = L"Windows.Media.Ocr.OcrEngine";

static HRESULT qi(void* obj, const GUID* iid, void** out) {
    IUnkVtbl* vt = *((IUnkVtbl**)obj);
    return vt->QueryInterface(obj, iid, out);
}
static ULONG rel(void* obj) {
    IUnkVtbl* vt = *((IUnkVtbl**)obj);
    return vt->Release(obj);
}
static HRESULT get_factory(const wchar_t* cn, const GUID* iid, void** out) {
    HSTRING hs = NULL;
    HRESULT hr;
    if (FAILED(WindowsCreateString(cn, (UINT)wcslen(cn), &hs)))
        return E_FAIL;
    hr = RoGetActivationFactory(hs, iid, out);
    WindowsDeleteString(hs);
    return hr;
}

/* agile Completed delegate (IUnknown + Invoke@slot3) + async_wait.
 * IAsyncOperation<T>: put_Completed=11, GetResults=13 (IAsyncInfo = slots 6-10,
 * layout from Windows.Foundation.winmd). */
typedef struct AgileDelegateVtbl {
    HRESULT (*QueryInterface)(void*, const GUID*, void**);
    ULONG (*AddRef)(void*);
    ULONG (*Release)(void*);
    HRESULT (*Invoke)(void*, void*, int);
} AgileDelegateVtbl;
typedef struct AgileDelegate {
    const AgileDelegateVtbl* lpVtbl;
    LONG ref;
    HANDLE event;
} AgileDelegate;
static GUID g_handler_iid;
static int g_handler_set = 0, g_invoke_status = -1;
static int is_base_iid(const GUID* iid) {
    static const GUID IA = {
        0x94EA2B94, 0xE9CC, 0x49E0, {0xC0, 0xFF, 0xEE, 0x64, 0xCA, 0x8F, 0x5B, 0x90}};
    static const GUID II = {
        0xAF86E2E5, 0xB12D, 0x4C6A, {0x9C, 0x5A, 0xD7, 0xAA, 0x65, 0x10, 0x1E, 0x90}};
    if (iid == NULL)
        return 1;
    if (!memcmp(iid, &IID_IUnknown, sizeof(GUID)))
        return 1;
    if (!memcmp(iid, &II, sizeof(GUID)))
        return 1;
    if (!memcmp(iid, &IA, sizeof(GUID)))
        return 1;
    return 0;
}
static void trace_iid(const char* what, const GUID* iid) {
    TRACE(L"[.] %hs iid={%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n", what,
          (unsigned long)iid->Data1, (unsigned)iid->Data2, (unsigned)iid->Data3,
          (unsigned)iid->Data4[0], (unsigned)iid->Data4[1], (unsigned)iid->Data4[2],
          (unsigned)iid->Data4[3], (unsigned)iid->Data4[4], (unsigned)iid->Data4[5],
          (unsigned)iid->Data4[6], (unsigned)iid->Data4[7]);
}
static HRESULT ad_QI(void* s, const GUID* iid, void** o) {
    AgileDelegate* h = (AgileDelegate*)s;
    if (o == NULL)
        return E_POINTER;
    if (iid == NULL) {
        *o = NULL;
        return E_NOINTERFACE;
    }
    if (g_verbose)
        trace_iid("delegate QI", iid);
    if (is_base_iid(iid)) {
        *o = s;
        h->lpVtbl->AddRef(s);
        return S_OK;
    }
    if (!g_handler_set) {
        g_handler_iid = *iid;
        g_handler_set = 1;
        *o = s;
        h->lpVtbl->AddRef(s);
        if (g_verbose)
            trace_iid("delegate bound to", iid);
        return S_OK;
    }
    if (!memcmp(iid, &g_handler_iid, sizeof(GUID))) {
        *o = s;
        h->lpVtbl->AddRef(s);
        return S_OK;
    }
    TRACE(L"[.] delegate QI refused non-handler iid\n");
    *o = NULL;
    return E_NOINTERFACE;
}
static ULONG ad_AddRef(void* s) {
    return (ULONG)InterlockedIncrement(&((AgileDelegate*)s)->ref);
}
static ULONG ad_Release(void* s) {
    return (ULONG)InterlockedDecrement(&((AgileDelegate*)s)->ref);
}
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): fixed COM ABI signature */
static HRESULT ad_Invoke(void* s, void* ai, int st) {
    (void)ai;
    TRACE(L"[.] delegate Invoke fired (status=%d)\n", st);
    g_invoke_status = st;
    SetEvent(((AgileDelegate*)s)->event);
    return S_OK;
}
static const AgileDelegateVtbl ad_vtbl = {ad_QI, ad_AddRef, ad_Release, ad_Invoke};
static AgileDelegate g_completed = {&ad_vtbl, 0, NULL};

/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): slot indices are a documented pair */
static HRESULT async_wait(IAsyncOp* op, const GUID* iid, const wchar_t* stage, void** result) {
    HRESULT hr;
    IAsyncOp* iface = NULL;
    IUnkVtbl* vt;
    if (result == NULL) {
        if (op)
            rel(op);
        return E_POINTER;
    }
    *result = NULL;
    if (op == NULL || op->lpVtbl == NULL) {
        if (op)
            rel(op);
        return E_FAIL;
    }
    if (g_completed.event == NULL) {
        g_completed.event = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (g_completed.event == NULL) {
            rel(op);
            return E_FAIL;
        }
    }
    /* The op's default interface is IAsyncInfo; the put_Completed/
     * GetResults methods live on the per-T IAsyncOperation<T> instantiation
     * view, reached by QueryInterface for the instantiation IID. On that
     * view: put_Completed = slot 6, get_Completed = 7, GetResults = 8. */
    vt = (IUnkVtbl*)op->lpVtbl;
    hr = vt->QueryInterface(op, iid, (void**)&iface);
    TRACE(L"[.] %ls: QI(IAsyncOperation<T> view) hr=0x%X\n", stage, (unsigned)hr);
    if (FAILED(hr) || iface == NULL) {
        rel(op);
        return FAILED(hr) ? hr : E_FAIL;
    }
    g_handler_set = 0;
    g_invoke_status = -1;
    ResetEvent(g_completed.event);
    TRACE(L"[.] %ls: awaiting\n", stage);
    /* slot 6 of the instantiation view = put_Completed (the get_Id field) */
    hr = ((HRESULT (*)(void*, void*))iface->lpVtbl->get_Id)(iface, &g_completed);
    if (FAILED(hr)) {
        rel(iface);
        rel(op);
        return hr;
    }
    {
        DWORD wr = WaitForSingleObject(g_completed.event, 60000);
        if (wr != WAIT_OBJECT_0 || g_invoke_status != 1) {
            if (wr == WAIT_TIMEOUT) {
                /* op (default view) is IAsyncInfo: get_Status=slot 7,
                 * get_ErrorCode=slot 8 - read the op's own state so a wedge
                 * can be told apart from a failed op. */
                int st = -1;
                HRESULT ec = 0;
                ((HRESULT (*)(void*, int*))op->lpVtbl->get_Status)(op, &st);
                ((HRESULT (*)(void*, HRESULT*))op->lpVtbl->get_ErrorCode)(op, &ec);
                TRACE(L"[.] %ls: 60 s timeout (op status=%d (0=Started "
                      L"1=Completed 2=Canceled 3=Error) errorcode=0x%X\n",
                      stage, st, (unsigned)ec);
            } else {
                TRACE(L"[.] %ls: completed handler fired with status %d\n", stage,
                      (int)g_invoke_status);
            }
            rel(iface);
            rel(op);
            return (wr == WAIT_TIMEOUT) ? HRESULT_FROM_WIN32(WAIT_TIMEOUT) : E_FAIL;
        }
    }
    TRACE(L"[.] %ls: done\n", stage);
    /* slot 8 of the instantiation view = GetResults (the get_ErrorCode field) */
    hr = ((HRESULT (*)(void*, void**))iface->lpVtbl->get_ErrorCode)(iface, result);
    rel(iface);
    rel(op);
    if (FAILED(hr) || *result == NULL) {
        *result = NULL;
        return FAILED(hr) ? hr : E_FAIL;
    }
    return S_OK;
}

static char* wide_to_utf8(const wchar_t* w, int wlen) {
    int n;
    char* b;
    if (wlen < 0)
        wlen = 0;
    n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
    if (n <= 0) {
        b = (char*)malloc(1);
        if (b)
            b[0] = '\0';
        return b;
    }
    b = (char*)malloc((size_t)n + 1);
    if (!b)
        return NULL;
    WideCharToMultiByte(CP_UTF8, 0, w, wlen, b, n, NULL, NULL);
    b[n] = '\0';
    return b;
}

static HRESULT run_ocr(const wchar_t* path, char** out_utf8) {
    HRESULT hr;
    wchar_t full[MAX_PATH];
    IFileRandomAccessStreamStatics* fras = NULL;
    HSTRING hsPath = NULL;
    IRandomAccessStream* stream = NULL;
    IAsyncOp* op = NULL;
    IBitmapDecoderStatics* decS = NULL;
    void* decObj = NULL;
    IBitmapDecoder* decoder = NULL;
    void* frameObj = NULL;
    IBitmapFrameWSB* frame = NULL;
    void* sbmp = NULL;
    IOcrEngineStatics* engS = NULL;
    void* engObj = NULL;
    IOcrEngine* engine = NULL;
    void* resObj = NULL;
    IOcrResult* result = NULL;
    HSTRING hsText = NULL;
    const wchar_t* wtext = NULL;
    UINT textLen = 0;

    if (path == NULL || out_utf8 == NULL)
        return E_POINTER;
    *out_utf8 = NULL;
    {
        DWORD n = GetFullPathNameW(path, MAX_PATH, full, NULL);
        if (n != 0 && n < MAX_PATH)
            path = full;
    }

    /* 1) FileRandomAccessStream.OpenAsync(path, Read) -> IRandomAccessStream */
    hr = get_factory(CLASS_FileRandomAccessStream, &IID_IFileRandomAccessStreamStatics,
                     (void**)&fras);
    TRACE(L"[.] factory FileRandomAccessStream hr=0x%X\n", (unsigned)hr);
    if (FAILED(hr)) {
        goto done;
    }
    if (FAILED(WindowsCreateString(path, (UINT)wcslen(path), &hsPath))) {
        hr = E_FAIL;
        goto done;
    }
    hr = fras->lpVtbl->OpenAsync(fras, hsPath, 0, (void**)&op);
    WindowsDeleteString(hsPath);
    hsPath = NULL;
    if (FAILED(hr)) {
        goto done;
    }
    hr = async_wait(op, &IID_IAsyncOp_IRandomAccessStream, L"FileRandomAccessStream.OpenAsync",
                    (void**)&stream);
    op = NULL;
    if (FAILED(hr) || stream == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }

    /* 2) BitmapDecoder.CreateAsync(stream) -> BitmapDecoder */
    hr = get_factory(CLASS_BitmapDecoder, &IID_IBitmapDecoderStatics, (void**)&decS);
    TRACE(L"[.] factory BitmapDecoder hr=0x%X\n", (unsigned)hr);
    if (FAILED(hr)) {
        goto done;
    }
    hr = decS->lpVtbl->CreateAsync(decS, stream, (void**)&op);
    if (FAILED(hr)) {
        goto done;
    }
    hr = async_wait(op, &IID_IAsyncOp_BitmapDecoder, L"BitmapDecoder.CreateAsync", &decObj);
    op = NULL;
    if (FAILED(hr) || decObj == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }
    hr = qi(decObj, &IID_IBitmapDecoder, (void**)&decoder);
    if (FAILED(hr) || decoder == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }

    /* 3) decoder.GetFrameAsync(0) -> BitmapFrame (QI IBitmapFrameWithSoftwareBitmap) */
    hr = decoder->lpVtbl->GetFrameAsync(decoder, 0, (void**)&op);
    if (FAILED(hr)) {
        goto done;
    }
    hr = async_wait(op, &IID_IAsyncOp_BitmapFrame, L"GetFrameAsync", &frameObj);
    op = NULL;
    if (FAILED(hr) || frameObj == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }
    hr = qi(frameObj, &IID_IBitmapFrameWithSoftwareBitmap, (void**)&frame);
    if (FAILED(hr) || frame == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }

    /* 4) frame.GetSoftwareBitmapAsync() -> SoftwareBitmap */
    hr = frame->lpVtbl->GetSoftwareBitmapAsync(frame, (void**)&op);
    if (FAILED(hr)) {
        goto done;
    }
    hr = async_wait(op, &IID_IAsyncOp_SoftwareBitmap, L"GetSoftwareBitmapAsync", &sbmp);
    op = NULL;
    if (FAILED(hr) || sbmp == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }

    /* 5) OcrEngine.TryCreateFromUserProfileLanguages() -> OcrEngine (sync) */
    hr = get_factory(CLASS_OcrEngine, &IID_IOcrEngineStatics, (void**)&engS);
    TRACE(L"[.] factory OcrEngine hr=0x%X\n", (unsigned)hr);
    if (FAILED(hr)) {
        goto done;
    }
    hr = engS->lpVtbl->TryCreateFromUserProfileLanguages(engS, &engObj);
    if (FAILED(hr) || engObj == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }
    hr = qi(engObj, &IID_IOcrEngine, (void**)&engine);
    if (FAILED(hr) || engine == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }

    /* 6) engine.RecognizeAsync(softwareBitmap) -> OcrResult */
    hr = engine->lpVtbl->RecognizeAsync(engine, sbmp, (void**)&op);
    if (FAILED(hr)) {
        goto done;
    }
    hr = async_wait(op, &IID_IAsyncOp_OcrResult, L"OcrEngine.RecognizeAsync", &resObj);
    op = NULL;
    if (FAILED(hr) || resObj == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }
    hr = qi(resObj, &IID_IOcrResult, (void**)&result);
    if (FAILED(hr) || result == NULL) {
        hr = (hr == S_OK) ? E_FAIL : hr;
        goto done;
    }

    /* 7) result.get_Text() -> HSTRING -> UTF-8 */
    hr = result->lpVtbl->get_Text(result, &hsText);
    if (FAILED(hr)) {
        goto done;
    }
    wtext = WindowsGetStringRawBuffer(hsText, &textLen);
    if (wtext == NULL) {
        *out_utf8 = (char*)malloc(1);
        if (*out_utf8)
            (*out_utf8)[0] = '\0';
        hr = S_OK;
    } else {
        *out_utf8 = wide_to_utf8(wtext, (int)textLen);
        if (*out_utf8 == NULL)
            hr = E_OUTOFMEMORY;
    }

done:
    if (hsText != NULL)
        WindowsDeleteString(hsText);
    if (result != NULL)
        rel(result);
    if (resObj != NULL)
        rel(resObj);
    if (engine != NULL)
        rel(engine);
    if (engObj != NULL)
        rel(engObj);
    if (engS != NULL)
        rel(engS);
    if (sbmp != NULL)
        rel(sbmp);
    if (frame != NULL)
        rel(frame);
    if (frameObj != NULL)
        rel(frameObj);
    if (decoder != NULL)
        rel(decoder);
    if (decObj != NULL)
        rel(decObj);
    if (op != NULL)
        rel(op);
    if (decS != NULL)
        rel(decS);
    if (stream != NULL)
        rel(stream);
    if (fras != NULL)
        rel(fras);
    if (hsPath != NULL)
        WindowsDeleteString(hsPath);
    return SUCCEEDED(hr) ? S_OK : hr;
}

int winrt_ocr_file(const wchar_t* path, char** out_utf8) {
    HRESULT hr;
    int ro_inited = 0;
    if (path == NULL || out_utf8 == NULL)
        return 1;
    *out_utf8 = NULL;
    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (hr == RPC_E_CHANGED_MODE)
        ro_inited = 0;
    else if (FAILED(hr))
        return (int)(unsigned int)hr;
    else
        ro_inited = 1;
    hr = run_ocr(path, out_utf8);
    if (ro_inited)
        RoUninitialize();
    return SUCCEEDED(hr) ? 0 : (int)(unsigned int)hr;
}

static void usage(const wchar_t* e) {
    (void)fprintf(stderr,
                  "Usage: %ls [--verbose|-v] <input_image> [output_txt]\n"
                  "  OCR an image using Windows.Media.Ocr and write the recognized\n"
                  "  text (UTF-8) to output_txt — or to stdout when no output path is\n"
                  "  given. OCR language from user profile. --verbose: per-stage\n"
                  "  tracing to stderr.\n",
                  e);
}

int wmain(int argc, wchar_t** argv) /* NOLINT(misc-use-internal-linkage) */
{
    char* text = NULL;
    int status;
    FILE* fout = NULL;
    size_t n = 0;
    const wchar_t* inpath = NULL;
    const wchar_t* outpath = NULL;
    int k;

    for (k = 1; k < argc; k++) {
        if (wcscmp(argv[k], L"--verbose") == 0 || wcscmp(argv[k], L"-v") == 0) {
            g_verbose = 1;
        } else if (wcscmp(argv[k], L"--help") == 0 || wcscmp(argv[k], L"-h") == 0) {
            usage((argc > 0) ? argv[0] : L"ocular-rip");
            return 0;
        } else if (inpath == NULL) {
            inpath = argv[k];
        } else if (outpath == NULL) {
            outpath = argv[k];
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    if (inpath == NULL) {
        usage(argv[0]);
        return 1;
    }
    (void)fwprintf(stderr, L"Input: %ls\n", inpath);
    if (outpath != NULL)
        (void)fwprintf(stderr, L"Output: %ls\n", outpath);
    else
        (void)fwprintf(stderr, L"Output: (stdout)\n");
    status = winrt_ocr_file(inpath, &text);
    if (status != 0) {
        (void)fwprintf(stderr, L"OCR failed (code 0x%X)\n", (unsigned)status);
        free(text);
        return 4;
    }
    n = strlen(text);
    if (outpath == NULL) {
        if (n > 0) {
            (void)fputs(text, stdout);
            (void)fputc('\n', stdout);
        }
        (void)fwprintf(stderr, L"OCR succeeded: %lu byte(s) -> stdout\n", (unsigned long)n);
        free(text);
        return 0;
    }
    fout = _wfopen(outpath, L"wb");
    if (fout == NULL) {
        (void)fwprintf(stderr, L"cannot open output '%ls'\n", outpath);
        free(text);
        return 5;
    }
    if (n > 0 && fwrite(text, 1, n, fout) != n) {
        (void)fwprintf(stderr, L"write failed\n");
        (void)fclose(fout);
        free(text);
        return 5;
    }
    if (fclose(fout) != 0) {
        free(text);
        return 5;
    }
    (void)fwprintf(stderr, L"OCR succeeded: %lu byte(s) -> %ls\n", (unsigned long)n, outpath);
    free(text);
    return 0;
}