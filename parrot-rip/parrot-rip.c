/*
 * parrot-rip.c - Standalone CLI: one spoken utterance -> text, using the inbox
 * desktop speech stack in two halves that are each proven to work on this
 * class of hardware:
 *
 *   capture:  MME waveIn (the legacy wave API) records a 60 s window of
 *             16 kHz/16-bit mono PCM from the default input device;
 *   engine:   SAPI5 in-proc SpInprocRecognizer with a dictation grammar, fed
 *             the captured audio as an ISpStreamFormat stream (SetInput), so
 *             the engine never touches the audio device itself.
 *
 * This split exists because on some Windows 11 hosts the in-proc engine's own
 * audio start wedges (SetDictationState(ACTIVE) returns a SPERR warning and
 * no SR events ever fire) even though MME capture works. Feeding the audio in
 * ourselves sidesteps that entirely: the engine processes the buffer and
 * emits SPEI_RECOGNITION + SPEI_END_SR_STREAM events, which we turn into
 * UTF-8 text on stdout.
 *
 * Pure C89, MinGW-w64, static CRT, imports: KERNEL32/msvcrt/ole32/oleaut32/
 * user32/winmm. No third-party code.
 *
 * Usage: parrot-rip.exe [--verbose|-v] [--timeout N] [out.txt]
 *
 * Exit codes: 0 utterance transcribed | 1 engine/usage/no-speech | 5 out-file
 * error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
#include <mmsystem.h>
#include <objidl.h>

#include <sapi.h>

/* SAPI CLSID/IIDs (documented values; MinGW's uuid lib doesn't carry them) */
static const GUID SC_CLSID_SpInprocRecognizer = {
    0x41b89b6b, 0x9399, 0x11d2, {0x96, 0x23, 0x00, 0xc0, 0x4f, 0x8e, 0xe6, 0x28}};
static const GUID SC_IID_ISpRecognizer = {
    0xc2b5f241, 0xdaa0, 0x4507, {0x9e, 0x16, 0x5a, 0x1e, 0xaa, 0x2b, 0x7a, 0x5c}};
static const GUID SC_IID_ISpEventSource = {
    0xbe7a9cce, 0x5f9e, 0x11d2, {0x96, 0x0f, 0x00, 0xc0, 0x4f, 0x8e, 0xe6, 0x28}};
/* SPDFID_WaveFormatEx: format-id GUID used with ISpStreamFormat::GetFormat */
static const GUID SC_IID_ISpStream_ = {
    0x12e3cca9, 0x7518, 0x44c5, {0xa5, 0xe7, 0xba, 0x5a, 0x79, 0xcb, 0x92, 0x9e}};
static const GUID SC_IID_ISpStreamFormat = {
    0xbed530be, 0x2606, 0x4f4d, {0xa1, 0xc0, 0x54, 0xc5, 0xcd, 0xa5, 0x56, 0x6f}};
static const GUID SC_SPDFID_WaveFormatEx = {
    0xc31adbae, 0x527f, 0x4dff, {0x84, 0x2c, 0x39, 0x09, 0x99, 0x59, 0x71, 0xc2}};

#define SAPI_LISTEN_MS 60000u /* capture window: one utterance + pauses */

static int g_verbose = 0; /* --verbose: stage-level tracing to stderr */
#define TRACE(...)                                                                                 \
    do {                                                                                           \
        if (g_verbose)                                                                             \
            (void)fwprintf(stderr, __VA_ARGS__);                                                   \
    } while (0)

typedef struct IUnkVtbl {
    HRESULT (*QueryInterface)(void*, const GUID*, void**);
    ULONG (*AddRef)(void*);
    ULONG (*Release)(void*);
} IUnkVtbl;
typedef struct IUnk {
    const IUnkVtbl* lpVtbl;
} IUnk;

static ULONG rel(void* obj) {
    return ((IUnk*)obj)->lpVtbl->Release(obj);
}

static char* wide_to_utf8(const wchar_t* w, int wlen) {
    int n;
    char* buf;
    if (wlen < 0)
        wlen = 0;
    n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
    if (n <= 0) {
        buf = (char*)malloc(1);
        if (buf)
            buf[0] = '\0';
        return buf;
    }
    buf = (char*)malloc((size_t)n + 1);
    if (!buf)
        return NULL;
    WideCharToMultiByte(CP_UTF8, 0, w, wlen, buf, n, NULL, NULL);
    buf[n] = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/* capture: waveIn 16 kHz / 16-bit / mono into a growable buffer       */
/* ------------------------------------------------------------------ */

#define CAP_RATE 16000
#define CAP_CH 1
#define CAP_BITS 16

typedef struct {
    unsigned char* data;
    size_t len;
    long peak;
} CapBuf;

static int cap_wavein(unsigned long listen_ms, CapBuf* out) {
    WAVEFORMATEX wf;
    HWAVEIN hwi = NULL;
    WAVEHDR wh[8];
    static unsigned char bufs[8][32000];
    MMRESULT r;
    int i;
    long peak = 0;
    unsigned char* acc = NULL;
    size_t acc_n = 0, acc_cap = 0;

    memset(out, 0, sizeof(*out));
    memset(&wf, 0, sizeof(wf));
    wf.wFormatTag = WAVE_FORMAT_PCM;
    wf.nChannels = CAP_CH;
    wf.nSamplesPerSec = CAP_RATE;
    wf.wBitsPerSample = CAP_BITS;
    wf.nBlockAlign = (WORD)(CAP_CH * CAP_BITS / 8);
    wf.nAvgBytesPerSec = wf.nSamplesPerSec * wf.nBlockAlign;

    r = waveInOpen(&hwi, WAVE_MAPPER, &wf, 0, 0, CALLBACK_NULL);
    TRACE(L"[.] capture: waveInOpen hr=0x%08X\n", (unsigned int)r);
    if (r != 0)
        return (int)r;
    memset(wh, 0, sizeof(wh));
    for (i = 0; i < 8; i++) {
        wh[i].lpData = (LPSTR)bufs[i];
        wh[i].dwBufferLength = sizeof(bufs[i]);
        waveInPrepareHeader(hwi, &wh[i], sizeof(wh[i]));
        waveInAddBuffer(hwi, &wh[i], sizeof(wh[i]));
    }
    r = waveInStart(hwi);
    TRACE(L"[.] capture: started (window %lu ms)\n", listen_ms);
    if (r != 0) {
        waveInClose(hwi);
        return (int)r;
    }
    {
        DWORD deadline = GetTickCount() + (DWORD)listen_ms;
        while (GetTickCount() < deadline) {
            int moved = 0;
            for (i = 0; i < 8; i++) {
                if (wh[i].dwFlags & WHDR_DONE) {
                    unsigned long n = wh[i].dwBytesRecorded;
                    unsigned long j;
                    short* smp = (short*)bufs[i];
                    if (n > 0) {
                        if (acc_n + n > acc_cap) {
                            acc_cap = (acc_cap ? acc_cap * 2u : 65536u) + n;
                            acc = (unsigned char*)realloc(acc, acc_cap);
                            if (!acc) {
                                waveInReset(hwi);
                                waveInClose(hwi);
                                return (int)E_OUTOFMEMORY;
                            }
                        }
                        memcpy(acc + acc_n, bufs[i], (size_t)n);
                        acc_n += n;
                        for (j = 0; j < n / 2; j++) {
                            long v = smp[j] < 0 ? -smp[j] : smp[j];
                            if (v > peak)
                                peak = v;
                        }
                    }
                    wh[i].dwFlags &= ~WHDR_DONE;
                    wh[i].dwBytesRecorded = 0;
                    waveInAddBuffer(hwi, &wh[i], sizeof(wh[i]));
                    moved = 1;
                }
            }
            if (!moved)
                Sleep(50);
        }
    }
    waveInReset(hwi);
    for (i = 0; i < 8; i++) {
        wh[i].dwFlags |= WHDR_PREPARED;
        waveInUnprepareHeader(hwi, &wh[i], sizeof(wh[i]));
    }
    waveInClose(hwi);

    out->peak = peak;
    out->data = acc;
    out->len = acc_n;
    TRACE(L"[.] capture: %lu bytes (%lu frames), peak=%ld\n", (unsigned long)acc_n,
          (unsigned long)(acc_n / 2), (long)peak);
    if (peak == 0 || acc_n == 0) {
        free(acc);
        out->data = NULL;
        return (int)HRESULT_FROM_WIN32(WAIT_TIMEOUT); /* pure silence */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* silence trim: keep only the speech portion (with 0.5 s pads)        */
/* ------------------------------------------------------------------ */

#define TRIM_THRESH 400       /* ~ -38 dBFS; low so weak /h/ and soft consonants count */
#define TRIM_PAD_FRAMES 16000 /* 1.0 s pre/post-roll at 16 kHz */

static void trim_silence(CapBuf* cap) {
    short* smp = (short*)cap->data;
    size_t n = cap->len / 2;
    size_t i, first = n, last = 0;
    size_t new_len;
    if (n == 0)
        return;
    for (i = 0; i < n; i++) {
        short s = smp[i];
        if (s < -TRIM_THRESH || s > TRIM_THRESH) {
            first = i;
            break;
        }
    }
    for (i = n; i > 0; i--) {
        short s = smp[i - 1];
        if (s < -TRIM_THRESH || s > TRIM_THRESH) {
            last = i;
            break;
        }
    }
    if (first >= last) { /* all silence (peak might be a single click) */
        return;
    }
    {
        size_t start = first > TRIM_PAD_FRAMES ? first - TRIM_PAD_FRAMES : 0;
        size_t end = last + TRIM_PAD_FRAMES < n ? last + TRIM_PAD_FRAMES : n;
        new_len = (end - start) * 2;
        TRACE(L"[.] trim: %lu -> %lu frames (speech from %.2fs to %.2fs)\n", (unsigned long)n,
              (unsigned long)(end - start), (double)start / CAP_RATE, (double)end / CAP_RATE);
        if (start > 0)
            memmove(cap->data, cap->data + start * 2, new_len);
        cap->len = new_len;
    }
}

/* ------------------------------------------------------------------ */
/* ISpStreamFormat implementation over the captured PCM bytes          */
/* ------------------------------------------------------------------ */

typedef struct {
    HRESULT (*QueryInterface)(void*, const GUID*, void**);
    ULONG (*AddRef)(void*);
    ULONG (*Release)(void*);
    HRESULT (*Read)(void*, void*, ULONG, ULONG*);
    HRESULT (*Write)(void*, const void*, ULONG, ULONG*);
    HRESULT (*Seek)(void*, LARGE_INTEGER, DWORD, ULARGE_INTEGER*);
    HRESULT (*SetSize)(void*, ULARGE_INTEGER);
    HRESULT (*CopyTo)(void*, IStream*, ULARGE_INTEGER, ULARGE_INTEGER*, ULARGE_INTEGER*);
    HRESULT (*Commit)(void*, DWORD);
    HRESULT (*Revert)(void*);
    HRESULT (*LockRegion)(void*, ULARGE_INTEGER, ULARGE_INTEGER, DWORD);
    HRESULT (*UnlockRegion)(void*, ULARGE_INTEGER, ULARGE_INTEGER, DWORD);
    HRESULT (*Stat)(void*, STATSTG*, DWORD);
    HRESULT (*Clone)(void*, IStream**);
    HRESULT (*GetFormat)(void*, GUID*, WAVEFORMATEX**);
} SpFmtVtbl;

typedef struct {
    const SpFmtVtbl* vtbl;
    LONG ref;
    unsigned char* wav;
    size_t len;
    size_t pos;
} SpFmtObj;

static const GUID IID_IStream_ = {
    0x0000000c, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static const GUID IID_ISeq_ = {
    0x0c733a30, 0x2a1c, 0x11ce, {0xad, 0xe5, 0x00, 0xaa, 0x00, 0x44, 0x77, 0x3d}};

static HRESULT sfmtQI(void* self, const GUID* iid, void** out) {
    SpFmtObj* o = (SpFmtObj*)self;
    if (!o || !out)
        return E_POINTER;
    if (!memcmp(iid, &IID_IUnknown, sizeof(GUID)) || !memcmp(iid, &IID_IStream_, sizeof(GUID)) ||
        !memcmp(iid, &IID_ISeq_, sizeof(GUID)) || !memcmp(iid, &SC_IID_ISpStream_, sizeof(GUID)) ||
        !memcmp(iid, &SC_IID_ISpStreamFormat, sizeof(GUID))) {
        *out = self;
        o->ref++;
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}
static ULONG sfmtAddRef(void* self) {
    return (ULONG)InterlockedIncrement(&((SpFmtObj*)self)->ref);
}
static ULONG sfmtRelease(void* self) {
    SpFmtObj* o = (SpFmtObj*)self;
    ULONG r = InterlockedDecrement(&o->ref);
    if (r == 0) {
        free(o->wav);
        free(o);
    }
    return (ULONG)r;
}
static HRESULT sfmtRead(void* self, void* pv, ULONG cb, ULONG* pcbRead) {
    SpFmtObj* o = (SpFmtObj*)self;
    ULONG avail;
    if (!pv || !pcbRead)
        return STG_E_INVALIDPOINTER;
    if (o->pos >= o->len) {
        *pcbRead = 0;
        return S_FALSE; /* end of stream */
    }
    avail = (ULONG)(o->len - o->pos);
    if (cb > avail)
        cb = avail;
    memcpy(pv, o->wav + o->pos, (size_t)cb);
    o->pos += cb;
    *pcbRead = cb;
    return S_OK;
}
static HRESULT sfmtWrite(void* self, const void* pv, ULONG cb, ULONG* pcbWritten) {
    (void)self;
    (void)pv;
    (void)cb;
    if (pcbWritten)
        *pcbWritten = 0;
    return STG_E_WRITEFAULT;
}
static HRESULT sfmtSeek(void* self, LARGE_INTEGER dlibMove, DWORD origin, ULARGE_INTEGER* newPos) {
    SpFmtObj* o = (SpFmtObj*)self;
    long long target;
    switch (origin) {
    case STREAM_SEEK_SET:
        target = (long long)dlibMove.QuadPart;
        break;
    case STREAM_SEEK_CUR:
        target = (long long)o->pos + dlibMove.QuadPart;
        break;
    case STREAM_SEEK_END:
        target = (long long)o->len + dlibMove.QuadPart;
        break;
    default:
        return STG_E_INVALIDFUNCTION;
    }
    if (target < 0)
        return STG_E_INVALIDFUNCTION;
    o->pos = (size_t)target;
    if (newPos)
        newPos->QuadPart = (ULONGLONG)o->pos;
    return S_OK;
}
static HRESULT sfmtSetSize(void* self, ULARGE_INTEGER sz) {
    (void)self;
    (void)sz;
    return STG_E_ACCESSDENIED;
}
static HRESULT sfmtCopyTo(void* self, IStream* d, ULARGE_INTEGER cb, ULARGE_INTEGER* rd,
                          ULARGE_INTEGER* wr) {
    (void)self;
    (void)d;
    (void)cb;
    if (rd)
        rd->QuadPart = 0;
    if (wr)
        wr->QuadPart = 0;
    return S_OK;
}
static HRESULT sfmtCommit(void* self, DWORD f) {
    (void)self;
    (void)f;
    return S_OK;
}
static HRESULT sfmtRevert(void* self) {
    (void)self;
    return S_OK;
}
static HRESULT sfmtLock(void* self, ULARGE_INTEGER a, ULARGE_INTEGER b, DWORD f) {
    (void)self;
    (void)a;
    (void)b;
    (void)f;
    return S_OK;
}
static HRESULT sfmtUnlock(void* self, ULARGE_INTEGER a, ULARGE_INTEGER b, DWORD f) {
    (void)self;
    (void)a;
    (void)b;
    (void)f;
    return S_OK;
}
static HRESULT sfmtStat(void* self, STATSTG* st, DWORD flag) {
    SpFmtObj* o = (SpFmtObj*)self;
    (void)flag;
    memset(st, 0, sizeof(*st));
    st->type = STGTY_STREAM;
    st->cbSize.QuadPart = (ULONGLONG)o->len;
    return S_OK;
}
static HRESULT sfmtClone(void* self, IStream** out) {
    (void)self;
    (void)out;
    return E_NOTIMPL;
}
static HRESULT sfmtGetFormat(void* self, GUID* pguid, WAVEFORMATEX** pwfx) {
    (void)self;
    *pguid = SC_SPDFID_WaveFormatEx;
    *pwfx = (WAVEFORMATEX*)CoTaskMemAlloc(sizeof(WAVEFORMATEX));
    if (!*pwfx)
        return E_OUTOFMEMORY;
    memset(*pwfx, 0, sizeof(WAVEFORMATEX));
    (*pwfx)->wFormatTag = WAVE_FORMAT_PCM;
    (*pwfx)->nChannels = CAP_CH;
    (*pwfx)->nSamplesPerSec = CAP_RATE;
    (*pwfx)->wBitsPerSample = CAP_BITS;
    (*pwfx)->nBlockAlign = (WORD)(CAP_CH * CAP_BITS / 8);
    (*pwfx)->nAvgBytesPerSec = CAP_RATE * CAP_CH * (CAP_BITS / 8);
    return S_OK;
}

static const SpFmtVtbl g_spfmt_vtbl = {
    sfmtQI,   sfmtAddRef,  sfmtRelease, sfmtRead,   sfmtWrite,
    sfmtSeek, sfmtSetSize, sfmtCopyTo,  sfmtCommit, sfmtRevert,
    sfmtLock, sfmtUnlock,  sfmtStat,    sfmtClone,  sfmtGetFormat,
};

static SpFmtObj* spfmt_create(unsigned char* wav, size_t len) {
    SpFmtObj* o = (SpFmtObj*)calloc(1, sizeof(SpFmtObj));
    if (!o)
        return NULL;
    o->vtbl = &g_spfmt_vtbl;
    o->ref = 1;
    o->wav = wav;
    o->len = len;
    o->pos = 0;
    return o;
}

/* ------------------------------------------------------------------ */
/* recognition: SpInprocRecognizer over the captured stream            */
/* ------------------------------------------------------------------ */

/* Handle one queued SAPI event; if it is RECOGNITION, copy out UTF-8 text
 * (joined with any previous text). Returns nonzero only when text captured.
 * The queue owns event object references; we release ours on use. */
static int sapi_take_event(SPEVENT* ev, char** out_utf8) {
    if (ev->eEventId != SPEI_RECOGNITION || ev->elParamType != SPET_LPARAM_IS_OBJECT ||
        !ev->lParam) {
        if (g_verbose && ev->eEventId == SPEI_RECOGNITION)
            (void)fprintf(stderr,
                          "[.] sapi RECOGNITION elParamType=%d lParam=%p (not extracting)\n",
                          (int)ev->elParamType, (void*)ev->lParam);
        return 0;
    }
    {
        LPARAM lp = ev->lParam;
        ISpRecoResult* r = (ISpRecoResult*)lp; /* NOLINT(performance-no-int-to-ptr) */
        LPWSTR ctext = NULL;
        HRESULT g = r->lpVtbl->GetText(r, 0, 0xFFFFFFFFu, TRUE, &ctext, NULL);
        int ok = 0;
        if (g_verbose)
            (void)fprintf(stderr, "[.] sapi GetText hr=0x%08X\n", (unsigned int)g);
        if (SUCCEEDED(g) && ctext) {
            char* piece = wide_to_utf8(ctext, (int)wcslen(ctext));
            if (g_verbose)
                (void)fprintf(stderr, "[.] sapi text=%S (len=%d)\n", ctext, (int)wcslen(ctext));
            if (piece) {
                size_t old = *out_utf8 ? strlen(*out_utf8) : 0;
                size_t add = strlen(piece);
                if (g_verbose)
                    (void)fprintf(stderr, "[.] sapi appending %d bytes (total so far %d)\n",
                                  (int)add, (int)old);
                *out_utf8 = (char*)realloc(*out_utf8, old + add + 3);
                if (*out_utf8) {
                    if (old > 0) {
                        (*out_utf8)[old] = ' ';
                        memcpy(*out_utf8 + old + 1, piece, add + 1);
                    } else {
                        memcpy(*out_utf8, piece, add + 1);
                    }
                    ok = 1;
                }
                free(piece);
            }
            CoTaskMemFree(ctext);
        }
        rel(r);
        return ok;
    }
}

static int sapi_process_stream(unsigned char* wav, size_t wav_len, char** out_utf8,
                               unsigned long wait_ms) {
    ISpRecognizer* reco = NULL;
    ISpRecoContext* ctx = NULL;
    ISpEventSource* es = NULL;
    ISpRecoGrammar* gram = NULL;
    SpFmtObj* stream = NULL;
    HRESULT hr;
    DWORDLONG deadline;
    int done = 0, ok = 0;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr == RPC_E_CHANGED_MODE) {
        /* another thread owns the apartment; in-proc SR still works */
    }

    hr = CoCreateInstance(&SC_CLSID_SpInprocRecognizer, NULL, CLSCTX_INPROC_SERVER,
                          &SC_IID_ISpRecognizer, (void**)&reco);
    TRACE(L"[.] sapi: SpInprocRecognizer hr=0x%08X\n", (unsigned int)hr);
    if (FAILED(hr) || !reco)
        goto done;

    hr = reco->lpVtbl->CreateRecoContext(reco, &ctx);
    TRACE(L"[.] sapi: CreateRecoContext hr=0x%08X\n", (unsigned int)hr);
    if (FAILED(hr) || !ctx)
        goto done;
    hr = (((IUnk*)ctx)->lpVtbl->QueryInterface)(ctx, &SC_IID_ISpEventSource, (void**)&es);
    if (FAILED(hr) || !es)
        goto done;
    /* ISpNotifySource::SetNotifyWin32Event() takes no parameters: it creates
     * an internal Win32 event inside SAPI that is set whenever SR events are
     * queued.  The handle is fetched below via GetNotifyEventHandle()
     * (vtable slot 9) and waited on with a timeout. */
    { /* slot 7 = IUnknown[0..2] + SetNotifySink + SetNotifyWindowMessage +
       * SetNotifyCallbackFunction + SetNotifyCallbackInterface + this */
        typedef HRESULT(STDMETHODCALLTYPE * SetNotifyWin32EventFn)(void*);
        SetNotifyWin32EventFn sne = (SetNotifyWin32EventFn)(*(void***)es)[7];
        hr = sne(es);
        TRACE(L"[.] sapi: SetNotifyWin32Event hr=0x%08X\n", (unsigned int)hr);
        if (FAILED(hr))
            goto done;
    }
    es->lpVtbl->SetInterest(es, SPFEI_ALL_SR_EVENTS, SPFEI_ALL_SR_EVENTS);

    stream = spfmt_create(wav, wav_len);
    if (!stream)
        goto done;
    hr = reco->lpVtbl->SetInput(reco, (IUnknown*)stream, FALSE);
    TRACE(L"[.] sapi: SetInput(our stream) hr=0x%08X\n", (unsigned int)hr);
    if (FAILED(hr))
        goto done;

    hr = ctx->lpVtbl->CreateGrammar(ctx, 0, &gram);
    if (FAILED(hr) || !gram)
        goto done;
    hr = gram->lpVtbl->LoadDictation(gram, L"", SPLO_STATIC);
    TRACE(L"[.] sapi: LoadDictation hr=0x%08X\n", (unsigned int)hr);
    if (FAILED(hr))
        goto done;
    { /* add common-words phrase list as a parallel rule to bias the engine
       * toward frequent English words (the Vista-era HMM engine needs hints) */
        SPSTATEHANDLE rule = NULL;
        static const wchar_t* common_words =
            L"hello|hi|hey|the|a|an|is|are|was|were|be|have|has|had|do|does|did|\n"
            L"I|you|he|she|it|we|they|me|him|her|us|them|my|your|his|this|that|\n"
            L"from|to|of|in|on|at|by|for|with|about|and|or|but|not|so|if|then|\n"
            L"other|side|world|test|computer|please|thanks|yes|no|okay|good|\n"
            L"one|two|three|four|five|time|day|night|today|tomorrow|yesterday";
        HRESULT h2 =
            gram->lpVtbl->GetRule(gram, NULL, 0, SPRAF_TopLevel | SPRAF_Active, TRUE, &rule);
        if (SUCCEEDED(h2) && rule) {
            HRESULT h3 = gram->lpVtbl->AddWordTransition(gram, rule, NULL, common_words, L"|",
                                                         SPWT_LEXICAL, 100.0f, NULL);
            HRESULT h4 = gram->lpVtbl->Commit(gram, 0);
            TRACE(L"[.] sapi: wordlist GetRule=0x%08X Add=0x%08X Commit=0x%08X\n", (unsigned int)h2,
                  (unsigned int)h3, (unsigned int)h4);
        }
    }
    hr = gram->lpVtbl->SetDictationState(gram, SPRS_ACTIVE);
    TRACE(L"[.] sapi: SetDictationState(ACTIVE) hr=0x%08X\n", (unsigned int)hr);
    if (FAILED(hr))
        goto done;

    { /* slot 9: ISpNotifySource::GetNotifyEventHandle() returns the internal
       * Win32 event that SAPI signals when events are queued.  We wait on it
       * with a timeout so the outer loop can enforce the deadline. */
        typedef HANDLE(STDMETHODCALLTYPE * GetNotifyEventHandleFn)(void*);
        GetNotifyEventHandleFn geh = (GetNotifyEventHandleFn)(*(void***)es)[9];
        HANDLE sapiEvent = geh(es);
        if (!sapiEvent)
            goto done;
        deadline = GetTickCount64() + wait_ms;
        while (!done && GetTickCount64() < deadline) {
            DWORD remain = (DWORD)(deadline - GetTickCount64());
            DWORD wr = WaitForSingleObject(sapiEvent, remain > 250 ? 250 : remain);
            if (wr != WAIT_OBJECT_0)
                continue;
            for (;;) {
                SPEVENT evt[8];
                ULONG fetched = 0, fi;
                es->lpVtbl->GetEvents(es, 8, evt, &fetched);
                if (fetched == 0)
                    break;
                for (fi = 0; fi < fetched; fi++) {
                    if (g_verbose)
                        (void)fprintf(stderr,
                                      "[.] sapi event id=%lu (38=RECOGNITION 34=END_STREAM)\n",
                                      (unsigned long)evt[fi].eEventId);
                    if (evt[fi].eEventId == SPEI_END_SR_STREAM)
                        done = 1; /* engine consumed the whole buffer */
                    if (sapi_take_event(&evt[fi], out_utf8))
                        ok = 1;
                }
            }
        }
    }
    if (!ok)
        hr = (HRESULT)0x80045052; /* SPERR-range: stream ended without recognition */

done:
    if (gram)
        gram->lpVtbl->SetDictationState(gram, SPRS_INACTIVE), rel(gram);
    if (es)
        rel(es);
    if (ctx)
        rel(ctx);
    if (reco)
        rel(reco);
    if (stream)
        sfmtRelease(stream); /* frees wav + object */
    CoUninitialize();
    if (ok)
        return 0;
    return SUCCEEDED(hr) ? (int)HRESULT_FROM_WIN32(WAIT_TIMEOUT) : (int)(unsigned int)hr;
}

/* ---- CLI ---- */

static void usage(const wchar_t* exe) {
    (void)fprintf(stderr,
                  "Usage: %ls [--verbose|-v] [--timeout N] [out.txt]\n"
                  "  Captures one utterance from the default microphone using the\n"
                  "  inbox SAPI5 dictation engine (SpInprocRecognizer) and prints\n"
                  "  the recognized text (UTF-8) to stdout (and to out.txt if given).\n"
                  "  --verbose/-v: stage-level tracing to stderr.\n"
                  "  --timeout N: max listening period in seconds (default 60; 1-86400).\n"
                  "  Offline and un-gated (no online-speech privacy consent needed).\n",
                  exe);
}

int wmain(int argc, wchar_t** argv) /* NOLINT(misc-use-internal-linkage) */
{
    char* text = NULL;
    FILE* fout = NULL;
    int status;
    const wchar_t* outname = NULL;
    unsigned long listen_ms = SAPI_LISTEN_MS;
    int k;
    CapBuf capbuf;

    for (k = 1; k < argc; k++) {
        if (wcscmp(argv[k], L"--verbose") == 0 || wcscmp(argv[k], L"-v") == 0) {
            g_verbose = 1;
        } else if (wcscmp(argv[k], L"--help") == 0 || wcscmp(argv[k], L"-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (wcscmp(argv[k], L"--timeout") == 0) {
            long secs;
            wchar_t* endp;
            if (k + 1 >= argc) {
                usage(argv[0]);
                return 1;
            }
            secs = wcstol(argv[++k], &endp, 10);
            if (endp == argv[k] || *endp != L'\0' || secs < 1 || secs > 86400) {
                usage(argv[0]);
                return 1;
            }
            listen_ms = (unsigned long)secs * 1000u;
        } else if (outname == NULL) {
            outname = argv[k];
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    (void)fwprintf(stderr, L"Listening (%lu s window)... one utterance.\n", listen_ms / 1000u);
    status = cap_wavein(listen_ms, &capbuf);
    if (status != 0) {
        if (status == (int)HRESULT_FROM_WIN32(WAIT_TIMEOUT))
            (void)fwprintf(stderr, L"no speech captured before the listen window elapsed\n");
        else
            (void)fwprintf(stderr, L"capture failed (code 0x%X)\n", (unsigned int)status);
        return 1;
    }
    TRACE(L"[.] peak=%ld audio present; trimming...\n", (long)capbuf.peak);
    trim_silence(&capbuf);
    TRACE(L"[.] trimmed: %lu bytes, recognizing...\n", (unsigned long)capbuf.len);
    {
        /* recognition deadline: at least 30 s even for short listen windows —
         * engine bring-up + processing of the trimmed buffer can outlast a
         * tiny --timeout; the flag bounds the listening period only. */
        unsigned long reco_ms = listen_ms < 30000u ? 30000u : listen_ms;
        status = sapi_process_stream(capbuf.data, capbuf.len, &text, reco_ms);
        capbuf.data = NULL; /* ownership transferred */
    }
    if (status != 0) {
        if (status == (int)HRESULT_FROM_WIN32(WAIT_TIMEOUT))
            (void)fwprintf(stderr, L"no speech recognized in the captured audio\n");
        else
            (void)fwprintf(stderr, L"recognition failed (code 0x%X)\n", (unsigned int)status);
        free(text);
        return 1;
    }

    if (text != NULL) {
        (void)fputs(text, stdout);
        (void)fputc('\n', stdout);
    }
    if (outname != NULL) {
        size_t n;
        fout = _wfopen(outname, L"wb");
        if (fout == NULL) {
            (void)fwprintf(stderr, L"cannot open output '%ls'\n", outname);
            free(text);
            return 5;
        }
        if (text != NULL) {
            n = strlen(text);
            if (n && fwrite(text, 1, n, fout) != n) {
                (void)fwprintf(stderr, L"write failed on %ls\n", outname);
                (void)fclose(fout);
                free(text);
                return 5;
            }
        }
        (void)fclose(fout);
        (void)fwprintf(stderr, L"wrote %lu byte(s) to %ls\n",
                       (unsigned long)(text ? strlen(text) : 0), outname);
    }
    free(text);
    return 0;
}