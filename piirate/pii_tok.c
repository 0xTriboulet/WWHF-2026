/*
 * pii_tok.c - Tokenizer core for piirate (pure C89, portable, no OS calls).
 * See pii_tok.h for the pipeline description and provenance.
 */
#include <stdlib.h>
#include <string.h>

#include "pii_tok.h"
#include "tok_data.h"

const char* const pii_default_labels[17] = {"phone number",
                                            "email address",
                                            "credit card number",
                                            "address",
                                            "social security number",
                                            "date of birth",
                                            "bank account number",
                                            "password",
                                            "pin code",
                                            "ip address",
                                            "dollar amount",
                                            "passport number",
                                            "driver license number",
                                            "tax id",
                                            "api key",
                                            "access token",
                                            "secret key"};

/* ------------------------------------------------------------------ */
/* UTF-8 decode                                                       */
/* ------------------------------------------------------------------ */

/* Decode one codepoint from p[0..n). On truncated/invalid sequences,
 * consumes 1 byte and yields U+FFFD (matches Rust's replacement behavior on
 * invalid input closely enough for our purposes: invalid UTF-8 never occurs
 * here because piirate decodes files to valid UTF-8 before tokenizing). */
static unsigned int u8_decode(const unsigned char* p, int n, int* clen) {
    unsigned int b0 = p[0], c;
    if (n <= 0) {
        *clen = 0;
        return 0xFFFD;
    }
    if (b0 < 0x80) {
        *clen = 1;
        return b0;
    }
    if (b0 < 0xC2) {
        *clen = 1; /* stray continuation / overlong 2-byte lead */
        return 0xFFFD;
    }
    if (b0 < 0xE0 && n >= 2) {
        c = ((b0 & 0x1F) << 6) | (p[1] & 0x3F);
        *clen = 2;
        return c;
    }
    if (b0 < 0xF0 && n >= 3) {
        c = ((b0 & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
        *clen = 3;
        return c;
    }
    if (b0 < 0xF5 && n >= 4) {
        c = ((b0 & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
        *clen = 4;
        return c;
    }
    *clen = 1;
    return 0xFFFD;
}

/* Unicode White_Space property (what Rust char::is_whitespace uses for the
 * tokenizers Strip normalizer). */
static int is_ws(unsigned int cp) {
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
/* NFKC precompiled charsmap (spm double-array trie)                  */
/* ------------------------------------------------------------------ */

static const unsigned char* g_trie_blob; /* u32 units start here */
static const unsigned char* g_norm_blob; /* \0-terminated entries */
static unsigned int g_norm_len;

static unsigned int cm_load32(const unsigned char* p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) |
           ((unsigned int)p[3] << 24);
}

static unsigned int cm_unit(unsigned long idx) { /* idx is a small trie offset */
    return cm_load32(g_trie_blob + (size_t)idx * 4u);
}

/* spm_precompiled ArrayUnit semantic accessors (bit layout per its lib.rs) */
#define CM_HAS_LEAF(u) ((((u) >> 8) & 1u) != 0)
#define CM_VALUE(u) ((u) & 0x7FFFFFFFu)
#define CM_LABEL(u) ((u) & (0x80000000u | 0xFFu))
#define CM_OFFSET(u) (((u) >> 10) << (((u) & 0x200u) >> 6))

/* Common-prefix search: returns the value of the FIRST (shortest) matching
 * prefix — replicating spm_precompiled::Precompiled::transform exactly
 * (results[0]); -1 when no prefix matches. key must not contain a 0 byte
 * (trie search stops at 0; codepoints never encode a 0 byte except NUL
 * itself, which has no mapping in this charsmap). */
static long cm_transform(const unsigned char* key, int klen) {
    unsigned long node_pos = 0;
    unsigned int unit;
    int i;
    unit = cm_unit(node_pos);
    node_pos ^= CM_OFFSET(unit);
    for (i = 0; i < klen; i++) {
        unsigned int c = key[i];
        if (c == 0)
            break;
        node_pos ^= c;
        unit = cm_unit(node_pos);
        if (CM_LABEL(unit) != (c & 0xFFu))
            return -1;
        node_pos ^= CM_OFFSET(unit);
        if (CM_HAS_LEAF(unit))
            return (long)CM_VALUE(cm_unit(node_pos)); /* first hit == shortest */
    }
    return -1;
}

static void cm_init(const unsigned char* blob, unsigned int blob_len) {
    /* layout: [u32 LE trie size][trie: u32 units][normalized blob, \0-sep] */
    unsigned int tsize = cm_load32(blob);
    (void)blob_len;
    g_trie_blob = blob + 4;
    g_norm_blob = blob + 4 + tsize;
    g_norm_len = PII_CHARSMAP_LEN - 4 - tsize;
}

/* ------------------------------------------------------------------ */
/* Piece hash table (open addressing, FNV-1a 64-bit)                  */
/* ------------------------------------------------------------------ */

#define HT_BITS 18
#define HT_SIZE (1u << HT_BITS)
#define HT_MASK (HT_SIZE - 1u)

static int* g_ht; /* slot -> vocab id, -1 = empty */
static double g_min_score;

static unsigned long long fnv64(const unsigned char* p, int n) {
    unsigned long long h = 1469598103934665603ull; /* FNV offset basis */
    int i;
    for (i = 0; i < n; i++) {
        h ^= (unsigned long long)p[i];
        h *= 1099511628211ull; /* FNV prime */
    }
    return h;
}

static int piece_lookup(const unsigned char* p, int n) {
    unsigned long long h = fnv64(p, n);
    unsigned int pos = (unsigned int)(h & HT_MASK);
    int probes = 0;
    for (;;) {
        int id = g_ht[pos];
        if (id < 0)
            return -1;
        if ((int)pii_tok_len[id] == n && memcmp(pii_tok_blob + pii_tok_off[id], p, (size_t)n) == 0)
            return id;
        pos = (pos + 1) & HT_MASK;
        if (++probes > (int)HT_SIZE)
            return -1;
    }
}

int pii_tok_init(void) {
    int i;
    static int inited = 0;
    if (inited)
        return 0;
    g_ht = (int*)malloc(sizeof(int) * HT_SIZE);
    if (!g_ht)
        return -1;
    for (i = 0; i < (int)HT_SIZE; i++)
        g_ht[i] = -1;
    g_min_score = 1e308;
    for (i = 0; i < (int)PII_N_VOCAB; i++) {
        const unsigned char* s = pii_tok_blob + pii_tok_off[i];
        int n = (int)pii_tok_len[i];
        unsigned long long h = fnv64(s, n);
        unsigned int pos = (unsigned int)(h & HT_MASK);
        while (g_ht[pos] >= 0)
            pos = (pos + 1) & HT_MASK;
        g_ht[pos] = i;
        if (pii_tok_score[i] < g_min_score)
            g_min_score = (double)pii_tok_score[i];
    }
    cm_init(pii_charsmap, PII_CHARSMAP_LEN);
    inited = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Normalization (Strip -> Precompiled NFKC -> collapse spaces)        */
/* ------------------------------------------------------------------ */

/* Normalize `in` (inlen bytes) into out buffer (cap bytes in+4 worst case
 * growth: charsmap entries can expand, e.g. Ⅷ → "VIII"); returns out bytes. */
static int normalize_word(const unsigned char* in, int inlen, unsigned char* out, int cap) {
    int s = 0, e = inlen, o = 0;
    int cl;
    /* Strip left/right over codepoints (tokenizers::Strip, White_Space) */
    while (s < e) {
        unsigned int cp = u8_decode(in + s, e - s, &cl);
        if (!is_ws(cp))
            break;
        s += cl;
    }
    while (e > s) {
        /* find start of last codepoint */
        int k = e - 1;
        while (k > s && (in[k] & 0xC0) == 0x80)
            k--;
        if (is_ws(u8_decode(in + k, e - k, &cl)))
            e = k;
        else
            break;
    }
    /* NFKC per codepoint (grapheme approximation: per codepoint) */
    while (s < e) {
        unsigned char tmp[8];
        long idx;
        (void)u8_decode(in + s, e - s, &cl);
        if (cl >= 1 && cl <= 5) { /* grapheme len < 6 branch */
            memcpy(tmp, in + s, (size_t)cl);
            idx = cm_transform(tmp, cl);
            if (idx >= 0) {
                /* append normalized entry (up to next NUL) */
                /* NOLINTBEGIN(clang-analyzer-security.ArrayBound) o/idx bounds-checked by the loop
                 * condition */
                while (idx < (long)g_norm_len && g_norm_blob[idx] != 0 && o < cap - 1)
                    out[o++] = g_norm_blob[idx++];
                /* NOLINTEND(clang-analyzer-security.ArrayBound) */
                s += cl;
                continue;
            }
        }
        memcpy(out + o, in + s, (size_t)cl);
        o += cl;
        if (o > cap)
            return -1;
        s += cl;
    }
    /* Replace / {2,}/ -> " " */
    {
        int w = 0, j = 0, run = 0;
        while (j < o) {
            unsigned char c = out[j];
            if (c == 0x20) {
                run++;
            } else {
                if (run > 0) {
                    out[w++] = 0x20; /* a run of spaces collapses to one */
                    run = 0;
                }
                out[w++] = c;
            }
            j++;
        }
        /* single spaces stay single; longer runs collapsed above */
        if (run > 1) /* unreachable given the loop, kept for clarity */
            out[w++] = 0x20;
        o = w;
    }
    return o;
}

/* ------------------------------------------------------------------ */
/* Unigram (optimized Viterbi, fuse unk)                              */
/* ------------------------------------------------------------------ */

#define UNK_PENALTY 10.0

typedef struct {
    double score;
    int starts_at; /* byte offset of this node's piece start; -1 = unset */
    int id;
} DPNode;

/* Viterbi over one Metaspace chunk (bytes b[0..n)); appends ids to out. */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters): deliberate arg order */
static int unigram_encode(const unsigned char* b, int n, int* out, int cap, int ocnt) {
    DPNode* dp;
    int pos, cnt = ocnt;
    double unk_score = g_min_score - UNK_PENALTY;
    int i;
    static int idstack[8704];
    int nstack = 0;

    if (n <= 0)
        return ocnt;
    dp = (DPNode*)malloc(sizeof(DPNode) * (size_t)(n + 1));
    if (!dp)
        return -1;
    for (i = 0; i <= n; i++) {
        dp[i].score = 0.0;
        dp[i].starts_at = -1;
        dp[i].id = 0;
    }
    pos = 0;
    while (pos < n) {
        double best_here = dp[pos].score; /* unconditional per Rust reference */
        int has_single = 0;
        int cl;
        int len;
        (void)u8_decode(b + pos, n - pos, &cl); /* mblen: utf8 char length */
        if (cl < 1)
            cl = 1;
        for (len = 1; len <= n - pos && len <= (int)PII_MAX_PIECE_BYTES; len++) {
            int id = piece_lookup(b + pos, len);
            double cand;
            DPNode* tn;
            if (id < 0)
                continue;
            cand = best_here + pii_tok_score[id];
            tn = &dp[pos + len];
            if (tn->starts_at < 0 || cand > tn->score) {
                tn->score = cand;
                tn->starts_at = pos;
                tn->id = id;
            }
            if (!has_single && len == cl)
                has_single = 1;
        }
        if (!has_single) {
            DPNode* tn = &dp[pos + cl];
            double cand = unk_score + best_here;
            if (cl <= n - pos && (tn->starts_at < 0 || cand > tn->score)) {
                tn->score = cand;
                tn->starts_at = pos;
                tn->id = PII_UNK_ID;
            }
        }
        pos += cl;
    }
    /* backtrack; fuse consecutive unk ids into one id (fuse_unk=true) */
    {
        int at = n;
        while (at > 0) {
            DPNode* nd = &dp[at];
            if (nd->starts_at < 0)
                break; /* cannot happen when unk exists */
            if (nstack >= 8704) {
                free(dp);
                return -1;
            }
            idstack[nstack++] = nd->id;
            at = nd->starts_at;
        }
    }
    for (i = nstack - 1; i >= 0; i--) {
        int id = idstack[i];
        if (id == PII_UNK_ID && cnt > ocnt && out[cnt - 1] == PII_UNK_ID)
            continue; /* fuse_unk: adjacent unks in this chunk -> single id */
        if (cnt >= cap) {
            free(dp);
            return -1;
        }
        out[cnt++] = id;
    }
    free(dp);
    return cnt;
}

/* ------------------------------------------------------------------ */
/* Word-level entry: normalize -> metaspace -> per-chunk unigram       */
/* ------------------------------------------------------------------ */

int pii_tok_encode_word(const char* word, int word_bytes, int* out, int cap) {
    static unsigned char norm[8448]; /* word cap 1024 bytes in; NFKC expands */
    static unsigned char meta[8704];
    int nl, ml;
    int cnt = 0;
    int i;
#define PII_MSPACE_BYTE ((unsigned char)0x20) /* ' ' */
#define PII_MSPACE0 ((unsigned char)0xE2)     /* ▁ = U+2581 = E2 96 81 */
#define PII_MSPACE1 ((unsigned char)0x96)
#define PII_MSPACE2 ((unsigned char)0x81)

    if (word == NULL || word_bytes < 0)
        return -1;

    /* literal added-token fast paths (verified: tokenizers resolves these
     * exact words to 128001/128002) */
    if (word_bytes == 7 && memcmp(word, "<<ENT>>", 7) == 0) {
        if (cap < 1)
            return -1;
        out[0] = PII_ENT_ID;
        return 1;
    }
    if (word_bytes == 7 && memcmp(word, "<<SEP>>", 7) == 0) {
        if (cap < 1)
            return -1;
        out[0] = PII_ENTSEP_ID;
        return 1;
    }
    if (word_bytes == 0)
        return 0;

    nl = normalize_word((const unsigned char*)word, word_bytes, norm, (int)sizeof(norm));
    if (nl < 0)
        return -1;
    if (nl == 0)
        return 0;

    /* Metaspace: ▁ prepend always; ' ' -> ▁; split ON ▁ keeping it leading */
    ml = 0;
    meta[ml++] = PII_MSPACE0;
    meta[ml++] = PII_MSPACE1;
    meta[ml++] = PII_MSPACE2;
    for (i = 0; i < nl; i++) {
        unsigned char c = norm[i];
        if (c == PII_MSPACE_BYTE) {
            meta[ml++] = PII_MSPACE0;
            meta[ml++] = PII_MSPACE1;
            meta[ml++] = PII_MSPACE2;
        } else if (i + 2 < nl && c == PII_MSPACE0 && norm[i + 1] == PII_MSPACE1 &&
                   norm[i + 2] == PII_MSPACE2) {
            /* literal ▁ in input: passes through as-is (tokenizers Metaspace
             * does not escape the replacement char) */
            meta[ml++] = c;
            meta[ml++] = norm[i + 1];
            meta[ml++] = norm[i + 2];
            i += 2;
        } else {
            meta[ml++] = c;
        }
        if (ml > (int)sizeof(meta) - 6)
            return -1;
    }

    /* chunks: each begins at ▁ boundary; last chunk also ends at end */
    {
        int start = 0;
        i = 3; /* just after the leading ▁ */
        for (;;) {
            if (i >= ml) {
                int r;
                if (start < ml) {
                    r = unigram_encode(meta + start, ml - start, out, cap, cnt);
                    if (r < 0)
                        return -1;
                    cnt = r;
                }
                break;
            }
            if (meta[i] == PII_MSPACE0 && i + 2 < ml && meta[i + 1] == PII_MSPACE1 &&
                meta[i + 2] == PII_MSPACE2) {
                int r = unigram_encode(meta + start, i - start, out, cap, cnt);
                if (r < 0)
                    return -1;
                cnt = r;
                start = i;
                i += 3;
            } else {
                i++;
            }
        }
    }
    return cnt;
}
