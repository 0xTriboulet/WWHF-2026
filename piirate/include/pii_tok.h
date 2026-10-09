/*
 * pii_tok.h - Tokenizer core for piirate (pure C89, portable, no OS calls).
 *
 * Faithful port of the HuggingFace `tokenizers` pipeline that ships with
 * blinkwrite-ai/gliner-small-pii-onnx-int8 (tokenizer.json):
 *   normalizer  = Strip(l+r, Unicode White_Space) -> Precompiled NFKC charsmap
 *                 (spm double-array trie, per codepoint) -> Replace / {2,} -> " "
 *   pretokenize = Metaspace (replace U+0020 with U+2581 (bytes E2 96 81),
 *                 prepend always, split on U+2581 keeping it at chunk start)
 *   model       = Unigram (optimized Viterbi, kUnkPenalty=10, fuse_unk=true,
 *                 byte_fallback=false, unk id 3)
 *   post        = NOT applied here (handled by the caller's template: caller
 *                 prepends [CLS]=1 / appends [SEP]=2).
 * Added tokens <<ENT>> (128001) / <<SEP>> (128002) are matched literally by
 * the caller before encoding (same net effect as tokenizers' AddedVocabulary
 * for these exact words).
 *
 * Grapheme-cluster iteration of the Rust normalizer is approximated by
 * per-codepoint iteration; for BMP characters (incl. all ASCII) the mapping
 * behavior is identical (verified against the reference tokenizer on the
 * regression cases in tools/).
 */
#ifndef PII_TOK_H
#define PII_TOK_H

#include "tok_ranges.h"

/* token ids (from tokenizer_config.json added_tokens) */
#define PII_PAD_ID 0
#define PII_CLS_ID 1
#define PII_SEP_ID 2
#define PII_UNK_ID 3
#define PII_MASK_ID 128000
#define PII_ENT_ID 128001
#define PII_ENTSEP_ID 128002

#ifdef __cplusplus
extern "C" {
#endif

/* One-time init: builds the piece hash table from the embedded tables
 * (tok_data.h). Returns 0 on success. */
int pii_tok_init(void);

/* Encode a single "word" (an opaque byte run; must NOT contain U+0020? —
 * spaces are legal: they are normalized to U+2581 by the Metaspace step, so
 * labels like "phone number" pass through this call as-is).
 * Appends token ids to `out` (cap entries), returns the number appended,
 * or -1 on capacity error. 0 is a valid result (empty after normalization). */
int pii_tok_encode_word(const char* word, int word_bytes, int* out, int cap);

/* The 17 default PII labels + threshold from the model's README. */
extern const char* const pii_default_labels[17];
#define PII_DEFAULT_THRESHOLD 0.2f

#ifdef __cplusplus
}
#endif
#endif /* PII_TOK_H */
