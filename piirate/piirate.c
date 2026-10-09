/*
 * piirate.c - Recursive directory PII scanner driven by an embedded ONNX
 * model (GLiNER span-level NER: blinkwrite-ai/gliner-small-pii-onnx-int8,
 * Apache-2.0; model weights are embedded as raw bytes in the generated
 * piirate_model_partNN.h files). Pure C89, MinGW-w64, ONNX Runtime C API via
 * Windows' inbox runtime (C:\Windows\System32\onnxruntime.dll — LoadLibrary
 * + OrtGetApiBase + GetApi(17) at run time; nothing is linked at build time).
 *
 * Usage: piirate.exe <dir> [--threshold 0.2] [--labels "a,b,c"] [--max-file-mb N]
 *
 * Pipeline per window (replicates GLiNER gliner_uni_encoder_span
 * preprocessing exactly; see README.md section 2):
 *   text -> words (regex \w+(?:[-_]\w+)*|\S) -> prompt = per label
 *   "<<ENT>> <label>" words then "<<SEP>>" -> per-word HF tokenizers chain
 *   (Strip/NFKC/space-collapse -> Metaspace ▁ -> Unigram Viterbi) ->
 *   [CLS] ids [SEP], words_mask (first subtoken of each text word, prompt
 *   skipped, 1-indexed), attention = 1, text_lengths = [n_words],
 *   span_idx = all (i, i+j) for j < 12, span_mask = (i+j < n_words) ->
 *   OrtApi.Run -> logits[1, words, 12, labels] -> sigmoid > threshold,
 *   valid spans (s+j+1 <= n_words), greedy non-overlap decode.
 * Findings print to stdout; progress/diagnostics to stderr.
 *
 * Exit codes: 0 scanned ok (zero findings is success) | 1 usage |
 *             2 directory open error | 4 model/ORT init error
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* Microsoft's MIT-licensed C API declarations (from the ONNX Runtime 1.29
 * release headers; only the two headers needed to type the OrtApi table).
 * piirate LINKS NOTHING at build time — the runtime is Windows' inbox
 * C:\Windows\System32\onnxruntime.dll, resolved with LoadLibrary at run
 * time (OrtGetApiBase + GetApi(PII_ORT_API_VERSION)). */
#include "onnxruntime_c_api.h"

#include "pii_tok.h"
#include "piirate_model.h"

/* ------------------------------------------------------------------ */
/* model constants (from gliner_config.json + the model's README)      */
/* ------------------------------------------------------------------ */
#define PII_MAX_WIDTH 12        /* span width cap: property of the weights  */
#define PII_MAX_SEQ 512         /* DeBERTa-v3 max_position_embeddings       */
#define PII_WINDOW_OVERLAP 32   /* words shared between consecutive windows */
#define PII_WORD_CAP_BYTES 1024 /* longer words are truncated (documented)  */
#define PII_MAX_LABELS 64
#define PII_MAX_DEPTH 32
#define PII_TOK_WORD_BUF 8704 /* pieces buffer for one word */

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void err_s(const char* s) {
    (void)fputs(s, stderr);
}

/* NOLINTBEGIN(concurrency-mt-unsafe): exit-from-fatal is by design */
static void die(void) {
    exit(4);
}
/* NOLINTEND(concurrency-mt-unsafe) */

static void* xmalloc(size_t n) {
    void* p = malloc(n ? n : 1);
    if (!p) {
        err_s("[x] out of memory\n");
        die();
    }
    return p;
}

static void* xrealloc(void* p, size_t n) {
    void* q = realloc(p, n ? n : 1);
    if (!q) {
        err_s("[x] out of memory\n");
        die();
    }
    return q;
}

static char* xstrdup(const char* s) {
    size_t n = strlen(s) + 1;
    char* d = (char*)xmalloc(n);
    memcpy(d, s, n);
    return d;
}

/* ------------------------------------------------------------------ */
/* UTF-8 + the exact Unicode \w table (generated; matches python re)   */
/* ------------------------------------------------------------------ */

static int u8_next(const unsigned char* p, int n, unsigned int* cp) {
    unsigned int b0;
    if (n <= 0)
        return 0;
    b0 = p[0];
    if (b0 < 0x80) {
        *cp = b0;
        return 1;
    }
    if (b0 < 0xC2) {
        *cp = 0xFFFD;
        return 1;
    }
    if (b0 < 0xE0 && n >= 2) {
        *cp = ((b0 & 0x1F) << 6) | (p[1] & 0x3F);
        return 2;
    }
    if (b0 < 0xF0 && n >= 3) {
        *cp = ((b0 & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
        return 3;
    }
    if (b0 < 0xF5 && n >= 4) {
        *cp = ((b0 & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
        return 4;
    }
    *cp = 0xFFFD;
    return 1;
}

static int is_word_char(unsigned int cp) {
    int lo = 0, hi = (int)PII_N_WRANGES - 1; /* ranges sorted, from tok_data.h */
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (cp < pii_wrange[mid][0])
            hi = mid - 1;
        else if (cp > pii_wrange[mid][1])
            lo = mid + 1;
        else
            return 1;
    }
    return 0;
}

static int is_ws_cp(unsigned int cp) {
    if (cp >= 0x09 && cp <= 0x0D)
        return 1;
    if (cp == 0x20 || cp == 0x85 || cp == 0xA0 || cp == 0x1680 || cp == 0x2028 || cp == 0x2029 ||
        cp == 0x202F || cp == 0x205F || cp == 0x3000)
        return 1;
    if (cp >= 0x2000 && cp <= 0x200A)
        return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* word list (GLiNER 'whitespace' splitter: \w+(?:[-_]\w+)*|\S)        */
/* ------------------------------------------------------------------ */

typedef struct {
    int* woff;          /* [2*n]: start,end byte offsets into the file text */
    int* wtok0;         /* per word: offset into all_ids */
    int* wcount;        /* per word: number of token pieces */
    long long* all_ids; /* piece ids of every word, concatenated */
    size_t all_ids_n, all_ids_cap;
    int nw, wcap;
} WordList;

static void wl_add(WordList* wl, int start, int end) {
    if (wl->nw >= wl->wcap) {
        wl->wcap = wl->wcap ? wl->wcap * 2 : 256;
        wl->woff = (int*)xrealloc(wl->woff, sizeof(int) * 2u * (size_t)wl->wcap);
    }
    wl->woff[2u * (size_t)wl->nw] = start;
    wl->woff[2u * (size_t)wl->nw + 1u] = end;
    wl->nw++;
}

/* continuation of a \w word run: bytes to consume past position i, or 0.
 * Implements the regex group (?:[-_]\w+)* — a '-'/'/'_' extends the word
 * only when followed by at least one word char. */
static int word_extend(const unsigned char* t, int i, int nbytes) {
    unsigned int cp, cp2;
    int adv, adv2;
    if (i >= nbytes)
        return 0;
    adv = u8_next(t + i, nbytes - i, &cp);
    if (is_word_char(cp))
        return adv;
    if ((cp == '-' || cp == '_') && i + adv < nbytes) {
        adv2 = u8_next(t + i + adv, nbytes - i - adv, &cp2);
        if (is_word_char(cp2))
            return adv + adv2;
    }
    return 0;
}

/* regex finditer(r"\w+(?:[-_]\w+)*|\S") over the utf8 text */
static void split_words(const char* text, int nbytes, WordList* wl) {
    const unsigned char* t = (const unsigned char*)text;
    int i = 0;
    unsigned int cp;
    wl->nw = 0;
    while (i < nbytes) {
        int adv = u8_next(t + i, nbytes - i, &cp);
        if (is_ws_cp(cp)) {
            i += adv;
            continue;
        }
        if (is_word_char(cp)) {
            int start = i;
            i += adv;
            while ((adv = word_extend(t, i, nbytes)) > 0)
                i += adv;
            wl_add(wl, start, i);
        } else {
            wl_add(wl, i, i + adv); /* \S: single non-space char */
            i += adv;
        }
    }
}

/* tokenize every word once; fill wtok0/wcount/all_ids */
static void wl_tokenize(WordList* wl, const char* text) {
    int* piece = (int*)xmalloc(sizeof(int) * PII_TOK_WORD_BUF);
    int i;
    wl->wtok0 = (int*)xmalloc(sizeof(int) * (size_t)wl->nw);
    wl->wcount = (int*)xmalloc(sizeof(int) * (size_t)wl->nw);
    wl->all_ids = NULL;
    wl->all_ids_n = wl->all_ids_cap = 0;
    for (i = 0; i < wl->nw; i++) {
        int off = wl->woff[2u * (size_t)i], n = wl->woff[2u * (size_t)i + 1u] - off;
        int k;
        if (n > PII_WORD_CAP_BYTES)
            n = PII_WORD_CAP_BYTES;
        k = pii_tok_encode_word(text + off, n, piece, PII_TOK_WORD_BUF);
        if (k < 0)
            k = 0; /* pathological word: contributes no tokens */
        if (wl->all_ids_n + (size_t)k > wl->all_ids_cap) {
            wl->all_ids_cap = (wl->all_ids_cap ? wl->all_ids_cap * 2 : 2048) + (size_t)k;
            wl->all_ids = (long long*)xrealloc(wl->all_ids, sizeof(long long) * wl->all_ids_cap);
        }
        {
            int j;
            for (j = 0; j < k; j++)
                wl->all_ids[wl->all_ids_n + (size_t)j] = piece[j];
        }
        wl->wtok0[i] = (int)wl->all_ids_n;
        wl->wcount[i] = k;
        wl->all_ids_n += (size_t)k;
    }
    free(piece);
}

static void wl_free(WordList* wl) {
    free(wl->woff);
    free(wl->wtok0);
    free(wl->wcount);
    if (wl->all_ids)
        free(wl->all_ids);
}

/* ------------------------------------------------------------------ */
/* prompt (GLiNER SpanProcessor.prepare_inputs for span mode markerV0) */
/* ------------------------------------------------------------------ */

typedef struct {
    long long* ids; /* prompt piece ids (no CLS/SEP) */
    int len;
    int words; /* prompt word count = 2 * nlabels + 1 */
    char** labels;
    int nlabels;
} Prompt;

static Prompt g_prompt;

static void prompt_build(const char** labels, int nlabels) {
    int cap = 4096;
    long long* ids = (long long*)xmalloc(sizeof(long long) * (size_t)cap);
    int piece[PII_TOK_WORD_BUF];
    int n = 0, li, k, j;
    char** labs = (char**)xmalloc(sizeof(char*) * (size_t)nlabels);
    for (li = 0; li < nlabels; li++) {
        const char* lab = labels[li];
        int wl = (int)strlen(lab);
        if (wl > PII_WORD_CAP_BYTES)
            wl = PII_WORD_CAP_BYTES;
        k = pii_tok_encode_word("<<ENT>>", 7, piece, PII_TOK_WORD_BUF);
        if (k != 1 || piece[0] != PII_ENT_ID) {
            err_s("[x] tokenizer broke on <<ENT>>\n");
            die();
        }
        if (n + 1 >= cap) {
            cap *= 2;
            ids = (long long*)xrealloc(ids, sizeof(long long) * (size_t)cap);
        }
        ids[n++] = PII_ENT_ID;
        k = pii_tok_encode_word(lab, wl, piece, PII_TOK_WORD_BUF);
        if (k < 0)
            k = 0;
        while (n + k >= cap) {
            cap *= 2;
            ids = (long long*)xrealloc(ids, sizeof(long long) * (size_t)cap);
        }
        for (j = 0; j < k; j++)
            ids[n++] = piece[j];
        labs[li] = xstrdup(lab);
    }
    ids[n++] = PII_ENTSEP_ID; /* "<<SEP>>" resolves to 128002 */
    g_prompt.ids = ids;
    g_prompt.len = n;
    g_prompt.words = 2 * nlabels + 1;
    g_prompt.labels = labs;
    g_prompt.nlabels = nlabels;
}

/* ------------------------------------------------------------------ */
/* ORT session (OrtApi v29)                                            */
/* ------------------------------------------------------------------ */

static const OrtApi* g_api;
/* pinned to the inbox Windows runtime (C:\Windows\System32\onnxruntime.dll
 * = ONNX Runtime 1.17.1 on Win11 24H2/25H2, which supports OrtApi 1..17).
 * Every OrtApi member piirate calls predates v17, so the table layout we
 * consume from the 1.29 header is ABI-forward-compatible. */
#define PII_ORT_API_VERSION 17u
static OrtEnv* g_env;
static OrtSession* g_session;
static OrtMemoryInfo* g_meminfo;
static OrtAllocator* g_alloc;
static char* g_in_names[6];
static const char* g_out_name2 = "logits";
static const char* const* g_out_names;

static void ort_die(const char* what, OrtStatus* st) {
    (void)fprintf(stderr, "[x] ORT error at %s: %s\n", what, g_api->GetErrorMessage(st));
    if (st)
        g_api->ReleaseStatus(st);
    die();
}

static unsigned char* model_assemble(void) {
    unsigned char* buf = (unsigned char*)xmalloc(PII_MODEL_SIZE);
    size_t off = 0;
    int i;
    for (i = 0; i < (int)PII_MODEL_PARTS; i++) {
        memcpy(buf + off, pii_model_parts[i].data, pii_model_parts[i].len);
        off += pii_model_parts[i].len;
    }
    if (off != (size_t)PII_MODEL_SIZE) {
        err_s("[x] embedded model size mismatch\n");
        die();
    }
    return buf;
}

static void ort_init(void) {
    OrtStatus* st;
    OrtSessionOptions* so = NULL;
    unsigned char* blob;
    size_t n_in = 0, n_out = 0, i;
    SYSTEM_INFO si;
    static const char* want[6] = {"input_ids",    "attention_mask", "words_mask",
                                  "text_lengths", "span_idx",       "span_mask_int64"};

    {
        const OrtApiBase* ab;
        typedef const OrtApiBase* (*GetApiBaseFn)(void); /* single calling convention */
        GetApiBaseFn get_base = NULL;
        HMODULE h = LoadLibraryW(L"onnxruntime.dll");
        if (!h) {
            (void)fprintf(
                stderr,
                "[x] LoadLibrary(onnxruntime.dll) failed gle=%lu — the ONNX Runtime ships "
                "inbox with Windows 11; nothing else is needed\n",
                (unsigned long)GetLastError());
            die();
        }
        /* LoadLibrary's reference count keeps the DLL loaded for the
         * process lifetime; the handle itself is only needed for the
         * GetProcAddress below, so nothing stores it. */
        get_base = (GetApiBaseFn)(void*)GetProcAddress(h, "OrtGetApiBase");
        if (!get_base) {
            err_s("[x] onnxruntime.dll exports no OrtGetApiBase (unexpected runtime)\n");
            die();
        }
        /* CastProcAddress: intentional function-pointer cast (Win32 pattern) */
        ab = get_base();
        g_api = ab->GetApi(PII_ORT_API_VERSION);
        if (!g_api) {
            (void)fprintf(stderr, "[x] inbox onnxruntime.dll does not support OrtApi %u\n",
                          PII_ORT_API_VERSION);
            die();
        }
    }
    st = g_api->CreateEnv(ORT_LOGGING_LEVEL_ERROR, "piirate", &g_env);
    if (st)
        ort_die("CreateEnv", st);
    st = g_api->CreateSessionOptions(&so);
    if (st)
        ort_die("CreateSessionOptions", st);
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors > 1)
        (void)g_api->SetIntraOpNumThreads(
            so, si.dwNumberOfProcessors / 2 > 8 ? 8 : (int)(si.dwNumberOfProcessors / 2));
    blob = model_assemble();
    st = g_api->CreateSessionFromArray(g_env, blob, PII_MODEL_SIZE, so, &g_session);
    free(blob);
    if (so)
        g_api->ReleaseSessionOptions(so);
    if (st)
        ort_die("CreateSessionFromArray (embedded 188 MiB int8 model)", st);
    st = g_api->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &g_meminfo);
    if (st)
        ort_die("CreateCpuMemoryInfo", st);
    st = g_api->GetAllocatorWithDefaultOptions(&g_alloc);
    if (st)
        ort_die("GetAllocatorWithDefaultOptions", st);
    st = g_api->SessionGetInputCount(g_session, &n_in);
    if (st)
        ort_die("SessionGetInputCount", st);
    if (n_in != 6) {
        (void)fprintf(stderr, "[x] expected 6 graph inputs, got %lu\n", (unsigned long)n_in);
        die();
    }
    for (i = 0; i < n_in; i++)
        g_in_names[i] = NULL;
    for (i = 0; i < n_in; i++) {
        char* nm = NULL;
        size_t s;
        int found = 0;
        st = g_api->SessionGetInputName(g_session, i, g_alloc, &nm);
        if (st)
            ort_die("SessionGetInputName", st);
        for (s = 0; s < 6; s++)
            if (strcmp(nm, want[s]) == 0) {
                g_in_names[s] = (char*)xstrdup(nm);
                found = 1;
            }
        g_api->AllocatorFree(g_alloc, (void*)nm);
        if (!found) {
            err_s("[x] unexpected graph input name\n");
            die();
        }
    }
    for (i = 0; i < 6; i++)
        if (!g_in_names[i]) {
            err_s("[x] missing expected graph input\n");
            die();
        }
    st = g_api->SessionGetOutputCount(g_session, &n_out);
    if (st)
        ort_die("SessionGetOutputCount", st);
    if (n_out != 1) {
        (void)fprintf(stderr, "[x] expected 1 graph output, got %lu\n", (unsigned long)n_out);
        die();
    }
    {
        char* nm = NULL;
        st = g_api->SessionGetOutputName(g_session, 0, g_alloc, &nm);
        if (st)
            ort_die("SessionGetOutputName", st);
        if (strcmp(nm, g_out_name2) != 0) {
            (void)fprintf(stderr, "[x] unexpected graph output '%s'\n", nm);
            g_api->AllocatorFree(g_alloc, (void*)nm);
            die();
        }
        g_api->AllocatorFree(g_alloc, (void*)nm);
        g_out_names = (const char* const*)&g_out_name2;
    }
}

/* ------------------------------------------------------------------ */
/* decode (GLiNER SpanDecoder, flat mode)                              */
/* ------------------------------------------------------------------ */

typedef struct {
    int s, e, c;
    float p;
    long order;
} Cand;

/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): qsort-mandated signature */
static int cmp_cand(const void* a, const void* b) {
    const Cand *x = (const Cand*)a, *y = (const Cand*)b;
    if (x->p > y->p)
        return -1;
    if (x->p < y->p)
        return 1;
    if (x->order < y->order)
        return -1;
    if (x->order > y->order)
        return 1;
    return 0;
}

/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): qsort-mandated signature */
static int cmp_cand_start(const void* a, const void* b) {
    const Cand *x = (const Cand*)a, *y = (const Cand*)b;
    return x->s - y->s;
}

typedef struct {
    int cs, ce, c;
} DedupKey;

static DedupKey* g_dedup;
static int g_ndedup;

/* Store-by-construction: the buffer always holds g_ndedup+1 entries here
 * (analyzer cannot size-track through our xrealloc wrapper). */
static int dedup_insert(int cs, int ce, int c) {
    int i;
    DedupKey* nb;
    for (i = 0; i < g_ndedup; i++)
        if (g_dedup[i].cs == cs && g_dedup[i].ce == ce && g_dedup[i].c == c)
            return 0;
    nb = (DedupKey*)xrealloc(g_dedup, sizeof(DedupKey) * ((size_t)g_ndedup + 1u));
    /* NOLINTBEGIN(clang-analyzer-security.ArrayBound) */
    nb[g_ndedup].cs = cs;
    nb[g_ndedup].ce = ce;
    nb[g_ndedup].c = c;
    /* NOLINTEND(clang-analyzer-security.ArrayBound) */
    g_dedup = nb;
    g_ndedup++;
    return 1;
}

static float sigmoidf(float x) {
    double d = (double)x;
    if (d >= 0.0)
        return (float)(1.0 / (1.0 + exp(-d)));
    return (float)(exp(d) / (1.0 + exp(d)));
}

/* Run one window (global words w0..w0+nw) through the model; print new
 * spans (dedup across windows by char-range+label). Returns count printed. */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): deliberate arg order */
static int infer_window(const char* path, const char* text, const WordList* wl, int w0, int nw,
                        float threshold, int* used_out) {
    int tbudget = PII_MAX_SEQ - 2 - g_prompt.len; /* piece budget for text words */
    long long *ids, *wm, *attn;
    int seq, i, j;
    size_t nspans;
    long long *sidx, *smask, *tlen;
    OrtValue* tin[6];
    OrtValue* outv = NULL;
    OrtStatus* st;
    int64_t sh2[2], sh_tl[2], sh3[3];
    float* logits;
    Cand* cands = NULL;
    int ncand = 0, ccand = 0, nkept, printed = 0, used_words;

    /* tokens for this window: prompt + words, bounded by the piece budget.
     * Never silently drop words: truncate at budget and report back. */
    used_words = nw;
    {
        int tpieces = 0;
        for (i = 0; i < nw; i++) {
            if (tpieces + wl->wcount[w0 + i] > tbudget) {
                used_words = i;
                break;
            }
            tpieces += wl->wcount[w0 + i];
        }
        if (used_words < 1)
            used_words = 1;
        *used_out = used_words;
    }
    seq = 1 + g_prompt.len + 1;
    for (i = 0; i < used_words; i++)
        seq += wl->wcount[w0 + i];

    ids = (long long*)xmalloc(sizeof(long long) * (size_t)seq);
    wm = (long long*)xmalloc(sizeof(long long) * (size_t)seq);
    attn = (long long*)xmalloc(sizeof(long long) * (size_t)seq);

    ids[0] = PII_CLS_ID;
    wm[0] = 0;
    memcpy(ids + 1, g_prompt.ids, sizeof(long long) * (size_t)g_prompt.len);
    memset(wm + 1, 0, sizeof(long long) * (size_t)g_prompt.len);
    {
        int p = 1 + g_prompt.len;
        for (i = 0; i < used_words; i++) {
            int k = wl->wcount[w0 + i];
            const long long* src = wl->all_ids + wl->wtok0[w0 + i];
            if (k > 0) {
                memcpy(ids + p, src, sizeof(long long) * (size_t)k);
                wm[p] = i + 1; /* first subtoken of text word i (1-indexed) */
                for (j = 1; j < k; j++)
                    wm[p + j] = 0;
                p += k;
            } else {
                /* zero-token word occupies no token slot; nothing to mark */
            }
        }
        ids[p] = PII_SEP_ID;
        wm[p] = 0;
    }

    nspans = (size_t)used_words * PII_MAX_WIDTH;
    sidx = (long long*)xmalloc(sizeof(long long) * 2 * nspans);
    smask = (long long*)xmalloc(sizeof(long long) * nspans);
    tlen = (long long*)xmalloc(sizeof(long long));
    tlen[0] = used_words;
    {
        size_t q = 0;
        for (i = 0; i < used_words; i++)
            for (j = 0; j < PII_MAX_WIDTH; j++) {
                sidx[2 * q] = i;
                sidx[2 * q + 1] = i + j;
                smask[q] = (i + j < used_words) ? 1 : 0;
                q++;
            }
    }

    sh2[0] = 1;
    sh2[1] = seq;
    sh_tl[0] = 1;
    sh_tl[1] = 1;
    sh3[0] = 1;
    sh3[1] = (int64_t)nspans;
    sh3[2] = 2;
    for (i = 0; i < seq; i++)
        attn[i] = 1;
    st = g_api->CreateTensorWithDataAsOrtValue(g_meminfo, ids, sizeof(long long) * (size_t)seq, sh2,
                                               2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &tin[0]);
    if (!st)
        st = g_api->CreateTensorWithDataAsOrtValue(g_meminfo, attn, sizeof(long long) * (size_t)seq,
                                                   sh2, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64,
                                                   &tin[1]);
    if (!st)
        st = g_api->CreateTensorWithDataAsOrtValue(g_meminfo, wm, sizeof(long long) * (size_t)seq,
                                                   sh2, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64,
                                                   &tin[2]);
    if (!st)
        st = g_api->CreateTensorWithDataAsOrtValue(g_meminfo, tlen, sizeof(long long), sh_tl, 2,
                                                   ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &tin[3]);
    if (!st)
        st = g_api->CreateTensorWithDataAsOrtValue(g_meminfo, sidx, sizeof(long long) * 2 * nspans,
                                                   sh3, 3, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64,
                                                   &tin[4]);
    if (!st) {
        int64_t sh_sm[2];
        sh_sm[0] = 1;
        sh_sm[1] = (int64_t)nspans;
        st = g_api->CreateTensorWithDataAsOrtValue(g_meminfo, smask, sizeof(long long) * nspans,
                                                   sh_sm, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64,
                                                   &tin[5]);
    }
    if (st)
        ort_die("CreateTensorWithDataAsOrtValue", st);

    /* tensors reference our buffers; free buffers only after ReleaseValue */
    {
        const char* const* inn = (const char* const*)g_in_names;
        st =
            g_api->Run(g_session, NULL, inn, (const OrtValue* const*)tin, 6, g_out_names, 1, &outv);
    }
    if (st)
        ort_die("Run", st);
    st = g_api->GetTensorMutableData(outv, (void**)&logits);
    if (st)
        ort_die("GetTensorMutableData", st);
    {
        OrtTensorTypeAndShapeInfo* ti = NULL;
        int64_t dims[4] = {0, 0, 0, 0};
        size_t nd = 0;
        st = g_api->GetTensorTypeAndShape(outv, &ti);
        if (st)
            ort_die("GetTensorTypeAndShape", st);
        g_api->GetDimensionsCount(ti, &nd);
        g_api->GetDimensions(ti, dims, 4);
        g_api->ReleaseTensorTypeAndShapeInfo(ti);
        if ((int)nd != 4 || dims[0] != 1 || dims[1] != used_words || dims[2] != PII_MAX_WIDTH ||
            dims[3] != g_prompt.nlabels) {
            (void)fprintf(stderr, "[x] unexpected logits shape %lldx%lldx%lldx%lld for %d words\n",
                          (long long)dims[0], (long long)dims[1], (long long)dims[2],
                          (long long)dims[3], used_words);
            die();
        }
    }

    /* sigmoid > threshold; valid span (s + width_index + 1 <= used_words) */
    for (i = 0; i < used_words; i++)
        for (j = 0; j < PII_MAX_WIDTH; j++) {
            int c;
            if (i + j + 1 > used_words)
                break;
            for (c = 0; c < g_prompt.nlabels; c++) {
                float lg =
                    logits[((size_t)i * PII_MAX_WIDTH + (size_t)j) * (size_t)g_prompt.nlabels +
                           (size_t)c];
                float p = sigmoidf(lg);
                if (p > threshold) {
                    if (ncand >= ccand) {
                        ccand = ccand ? ccand * 2 : 256;
                        cands = (Cand*)xrealloc(cands, sizeof(Cand) * (size_t)ccand);
                    }
                    cands[ncand].s = i;
                    cands[ncand].e = i + j;
                    cands[ncand].c = c;
                    cands[ncand].p = p;
                    cands[ncand].order = ncand;
                    ncand++;
                }
            }
        }
    g_api->ReleaseValue(outv);
    for (i = 0; i < 6; i++)
        g_api->ReleaseValue(tin[i]);
    free(ids);
    free(wm);
    free(attn);
    free(sidx);
    free(smask);
    free(tlen);

    if (ncand == 0)
        return 0;
    qsort(cands, (size_t)ncand, sizeof(Cand), cmp_cand);
    {
        Cand* kept = (Cand*)xmalloc(sizeof(Cand) * (size_t)ncand);
        nkept = 0;
        for (i = 0; i < ncand; i++) {
            int ok = 1;
            for (j = 0; j < nkept; j++)
                if (!(cands[i].s > kept[j].e || kept[j].s > cands[i].e)) {
                    ok = 0;
                    break;
                }
            if (ok)
                kept[nkept++] = cands[i];
        }
        qsort(kept, (size_t)nkept, sizeof(Cand), cmp_cand_start);
        for (i = 0; i < nkept; i++) {
            int gs = wl->woff[2u * (size_t)(w0 + kept[i].s)];
            int ge = wl->woff[2u * (size_t)(w0 + kept[i].e) + 1u];
            if (dedup_insert(gs, ge, kept[i].c)) {
                (void)printf("%s -> %s (%.4f): \"", path, g_prompt.labels[kept[i].c],
                             (double)kept[i].p);
                (void)fwrite(text + gs, 1, (size_t)(ge - gs), stdout);
                (void)printf("\"\n");
                printed++;
            }
        }
        free(kept);
    }
    free(cands);
    return printed;
}

/* ------------------------------------------------------------------ */
/* file handling / windowing                                           */
/* ------------------------------------------------------------------ */

static int g_max_file_mb;
static long g_files_seen, g_files_failed, g_findings;

/* Read a file fully (cap), decode UTF-16LE BOM / strip UTF-8 BOM, else pass
 * bytes. Returns malloc'd buffer + length, or NULL (empty/unreadable). */
static unsigned char* read_file_utf8(HANDLE h, long maxbytes, int* out_len) {
    unsigned char* raw;
    DWORD rd = 0;
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz))
        return NULL;
    if (sz.QuadPart > (LONGLONG)maxbytes)
        sz.QuadPart = (LONGLONG)maxbytes;
    if (sz.QuadPart == 0)
        return NULL;
    raw = (unsigned char*)xmalloc((size_t)sz.QuadPart + 4);
    if (!ReadFile(h, raw, (DWORD)sz.QuadPart, &rd, NULL) || rd < 1) {
        free(raw);
        return NULL;
    }
    /* NOLINTNEXTLINE(clang-analyzer-security.ArrayBound): buffer is rd+4 bytes */
    raw[rd] = 0;
    if (rd >= 4 && raw[0] == 0xFF && raw[1] == 0xFE && (rd % 2) == 0) {
        int wchars = (int)(rd - 2) / 2;
        int need;
        need =
            WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)(raw + 2), wchars, NULL, 0, NULL, NULL);
        unsigned char* u8;
        if (need <= 0)
            need = wchars * 4;
        u8 = (unsigned char*)xmalloc((size_t)need + 4);
        need = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)(raw + 2), wchars, (char*)u8, need,
                                   NULL, NULL);
        free(raw);
        *out_len = (int)need;
        return u8;
    }
    if (rd >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF) {
        memmove(raw, raw + 3, rd - 3);
        *out_len = (int)rd - 3;
        return raw;
    }
    /* heuristic UTF-16LE *without* BOM: if the first KB is mostly NULs at odd
     * byte offsets (ASCII text in UTF-16LE), transcode as UTF-16LE */
    if (rd >= 16 && ((DWORD)rd & 1u) == 0) {
        DWORD probe = rd < 1024 ? (DWORD)rd : 1024;
        DWORD odd_nul = 0, pk;
        for (pk = 1; pk < probe; pk += 2)
            if (raw[pk] == 0)
                odd_nul++;
        if (odd_nul * 10u > probe) { /* >50% NUL at odd offsets */
            int wchars = (int)rd / 2;
            int need =
                WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)raw, wchars, NULL, 0, NULL, NULL);
            unsigned char* u8;
            if (need <= 0)
                need = wchars * 4;
            u8 = (unsigned char*)xmalloc((size_t)need + 4);
            need = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)raw, wchars, (char*)u8, need,
                                       NULL, NULL);
            free(raw);
            *out_len = (int)need;
            return u8;
        }
    }
    *out_len = (int)rd;
    return raw;
}

static int scan_file(const wchar_t* wpath, float threshold) {
    HANDLE h;
    unsigned char* text;
    int tlen = 0, total = 0;
    char upath[4096];
    WordList wl;
    int conv, w0;
    int win_words;

    conv = WideCharToMultiByte(CP_UTF8, 0, wpath, -1, upath, (int)sizeof(upath), NULL, NULL);
    if (conv <= 0) {
        err_s("[x] path conversion failed\n");
        return -1;
    }
    h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    text = read_file_utf8(h, (long)g_max_file_mb * 1024L * 1024L, &tlen);
    CloseHandle(h);
    if (!text || tlen <= 0) {
        if (text)
            free(text);
        return 0;
    }

    memset(&wl, 0, sizeof(wl));
    split_words((const char*)text, tlen, &wl);
    wl_tokenize(&wl, (const char*)text);
    if (wl.nw <= 0) {
        free(text);
        wl_free(&wl);
        return 0;
    }
    g_ndedup = 0;
    g_dedup = NULL;

    /* window sizing: prompt pieces + 2 pieces/word average estimate; the
     * hard token budget is enforced per-window in infer_window */
    win_words = (PII_MAX_SEQ - 2 - g_prompt.len) / 2;
    if (win_words < 8)
        win_words = 8;
    if (win_words < PII_WINDOW_OVERLAP + 8)
        win_words = PII_WINDOW_OVERLAP + 8;

    w0 = 0;
    while (w0 < wl.nw) {
        int nw = wl.nw - w0;
        int used = nw, step;
        if (nw > win_words)
            nw = win_words;
        total += infer_window(upath, (const char*)text, &wl, w0, nw, threshold, &used);
        if (w0 + used >= wl.nw)
            break;
        step = used - PII_WINDOW_OVERLAP;
        if (step < 1)
            step = 1;
        if (w0 + step <= w0)
            step = 1;
        w0 += step;
    }
    if (g_dedup) {
        free(g_dedup);
        g_dedup = NULL;
        g_ndedup = 0;
    }
    free(text);
    wl_free(&wl);
    (void)fprintf(stderr, "[.] %s: %d finding(s)\n", upath, total);
    return total;
}

/* recursive walk (wide-char); no junction/symlink following */
/* NOLINTNEXTLINE(misc-no-recursion): directory walk, depth-bounded (PII_MAX_DEPTH) */
static void scan_dir(const wchar_t* dir, int depth, float threshold) {
    wchar_t pat[2048], sub[2048];
    WIN32_FIND_DATAW fd;
    HANDLE fh;
    int r;
    if (depth > PII_MAX_DEPTH)
        return;
    r = _snwprintf(pat, 2048, L"%s\\*", dir);
    if (r < 0)
        return;
    fh = FindFirstFileW(pat, &fd);
    if (fh == INVALID_HANDLE_VALUE)
        return;
    do {
        int k;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        _snwprintf(sub, 2048, L"%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_dir(sub, depth + 1, threshold);
        } else {
            g_files_seen++;
            k = scan_file(sub, threshold);
            if (k < 0) {
                g_files_failed++;
                (void)fprintf(stderr, "[x] unreadable, skipped\n");
            } else {
                g_findings += k;
            }
        }
    } while (FindNextFileW(fh, &fd));
    FindClose(fh);
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

/* labels[] entries are heap only when they came from --labels parsing;
 * callers only invoke this with parsed labels (n>0), never the defaults. */
static void free_labels(const char** labels, int n) {
    int i;
    for (i = 0; i < n; i++)
        free((void*)labels[i]);
}

static void usage(const wchar_t* exe) {
    (void)fprintf(
        stderr,
        "Usage: %ls <directory> [--threshold 0.2] [--labels \"a,b,c\"] [--max-file-mb 4]\n"
        "  Recursively scan <directory> for PII with the embedded GLiNER int8 model\n"
        "  (blinkwrite-ai/gliner-small-pii-onnx-int8, Apache-2.0) via ONNX Runtime.\n"
        "  Findings print to stdout: <path> -> <label> (score): \"<span>\"\n"
        "  Default labels: the 17-label PII set from the model README.\n"
        "  Exit: 0 ok (zero findings is success) | 1 usage | 2 dir error | 4 init error.\n",
        exe);
}

/* split wide csv on ','/';' with surrounding-space trim → utf8 labels */
static int parse_labels(const wchar_t* csv, const char** labels, int cap) {
    int n = 0;
    const wchar_t* p = csv;
    while (*p && n < cap) {
        wchar_t buf[256];
        size_t a = 0;
        while (*p == L' ')
            p++;
        while (*p && *p != L',' && *p != L';' && a < 255)
            buf[a++] = *p++;
        while (a > 0 && buf[a - 1] == L' ')
            a--;
        buf[a] = 0;
        if (*p == L',' || *p == L';')
            p++;
        if (a == 0)
            continue;
        {
            char u8[1024];
            int nn = WideCharToMultiByte(CP_UTF8, 0, buf, -1, u8, (int)sizeof(u8), NULL, NULL);
            if (nn <= 0)
                continue;
            labels[n++] = xstrdup(u8);
        }
    }
    return n;
}

int wmain(int argc, wchar_t** argv) /* NOLINT(misc-use-internal-linkage) */
{
    const wchar_t* dir = NULL;
    float threshold = PII_DEFAULT_THRESHOLD;
    const char* labels[PII_MAX_LABELS];
    int nlabels = 0, i, custom_labels = 0; /* set below once labels are known */
    DWORD fa;

    if (argc < 2) {
        usage((argc > 0) ? argv[0] : L"piirate");
        return 1;
    }
    g_max_file_mb = 4;
    for (i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--threshold") == 0 && i + 1 < argc) {
            double t = wcstod(argv[++i], NULL);
            if (t < 0.0 || t > 1.0) {
                err_s("[x] --threshold must be in [0,1]\n");
                free_labels(labels, nlabels);
                return 1;
            }
            threshold = (float)t;
        } else if (wcscmp(argv[i], L"--labels") == 0 && i + 1 < argc) {
            nlabels = parse_labels(argv[++i], labels, PII_MAX_LABELS);
            if (nlabels == 0) {
                err_s("[x] --labels parsed to zero labels\n");
                free_labels(labels, nlabels);
                return 1;
            }
        } else if (wcscmp(argv[i], L"--max-file-mb") == 0 && i + 1 < argc) {
            g_max_file_mb = _wtoi(argv[++i]);
            if (g_max_file_mb < 1 || g_max_file_mb > 512) {
                err_s("[x] --max-file-mb must be 1..512\n");
                free_labels(labels, nlabels);
                return 1;
            }
        } else if (wcscmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"-h") == 0) {
            usage(argv[0]);
            free_labels(labels, nlabels);
            return 0;
        } else if (argv[i][0] != L'-') {
            dir = argv[i];
        } else {
            (void)fprintf(stderr, "[x] unknown switch '%ls'\n", argv[i]);
            usage(argv[0]);
            free_labels(labels, nlabels);
            return 1;
        }
    }
    if (!dir) {
        usage(argv[0]);
        free_labels(labels, nlabels);
        return 1;
    }
    fa = GetFileAttributesW(dir);
    if (fa == INVALID_FILE_ATTRIBUTES || !(fa & FILE_ATTRIBUTE_DIRECTORY)) {
        err_s("[x] not a directory\n");
        free_labels(labels, nlabels);
        return 2;
    }
    if (nlabels == 0) {
        for (i = 0; i < 17; i++)
            labels[i] = pii_default_labels[i];
        nlabels = 17;
        custom_labels = 0;
    } else {
        custom_labels = 1;
    }

    if (pii_tok_init() != 0) {
        err_s("[x] tokenizer init failed\n");
        free_labels(labels, custom_labels ? nlabels : 0);
        return 4;
    }
    prompt_build(labels, nlabels);
    if (custom_labels) /* prompt_build already copied them into g_prompt */
        free_labels(labels, nlabels);
    ort_init();
    (void)fprintf(stderr,
                  "[*] piirate: %u-byte embedded model (sha256 %s), inbox onnxruntime.dll, "
                  "OrtApi %u, %d labels, threshold %.2f\n",
                  (unsigned)PII_MODEL_SIZE, PII_MODEL_SHA256, PII_ORT_API_VERSION, nlabels,
                  (double)threshold);
    scan_dir(dir, 0, threshold);
    (void)fprintf(stderr, "[*] done: %ld file(s) scanned, %ld finding(s), %ld unreadable\n",
                  g_files_seen, g_findings, g_files_failed);
    for (i = 0; i < g_prompt.nlabels; i++)
        free((void*)g_prompt.labels[i]);
    free((void*)g_prompt.labels);
    free((void*)g_prompt.ids);
    return 0;
}
