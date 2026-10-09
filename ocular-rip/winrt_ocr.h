/*
 * winrt_ocr.h - Windows.Media.Ocr WinRT COM ABI for ocular-rip (pure C89),
 * the image->text (OCR) binary. This engine ships inbox in Windows 10 1607+.
 *
 * All IIDs below were extracted from the inbox OS WinMetadata winmd files
 * (C:\Windows\System32\WinMetadata\{Windows.Storage,Windows.Graphics,
 * Windows.Media}.winmd) by parsing the ECMA-335 metadata directly (Interface
 * IIDs from the GuidAttribute custom attribute, method order from the
 * MethodDef table = COM vtable order).
 * Slot numbers are each interface's own methods starting at slot 6 (these
 * interfaces require only IInspectable). The *Async ops inherit IAsyncInfo
 * (5 methods, slots 6-10, from Windows.Foundation.winmd), so
 * put_Completed=11 / GetResults=13 for IAsyncOperation<T>.
 */
#ifndef WINRT_OCR_H
#define WINRT_OCR_H

#include <windows.h>
#include <winstring.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IIDs (extracted from inbox WinMetadata winmd files) */
const GUID IID_IFileRandomAccessStreamStatics = {
    0x73550107,
    0x3B57,
    0x4B5D,
    {0x83, 0x45, 0x55, 0x4D, 0x2F, 0xC6, 0x21,
     0xF0}}; /* Windows.Storage.Streams.IFileRandomAccessStreamStatics */
const GUID IID_IBitmapDecoderStatics = {
    0x438CCB26,
    0xBCEF,
    0x4E95,
    {0xBA, 0xD6, 0x23, 0xA8, 0x22, 0xE5, 0x8D,
     0x01}}; /* Windows.Graphics.Imaging.IBitmapDecoderStatics */
const GUID IID_IBitmapDecoder = {
    0xACEF22BA,
    0x1D74,
    0x4C91,
    {0x9D, 0xFC, 0x96, 0x20, 0x74, 0x52, 0x33, 0xE6}}; /* Windows.Graphics.Imaging.IBitmapDecoder */
const GUID IID_IBitmapFrameWithSoftwareBitmap = {
    0xFE287C9A,
    0x420C,
    0x4963,
    {0x87, 0xAD, 0x69, 0x14, 0x36, 0xE0, 0x83,
     0x83}}; /* Windows.Graphics.Imaging.IBitmapFrameWithSoftwareBitmap */
const GUID IID_IOcrEngineStatics = {
    0x5BFFA85A,
    0x3384,
    0x3540,
    {0x99, 0x40, 0x69, 0x91, 0x20, 0xD4, 0x28, 0xA8}}; /* Windows.Media.Ocr.IOcrEngineStatics */
const GUID IID_IOcrEngine = {
    0x5A14BC41,
    0x5B76,
    0x3140,
    {0xB6, 0x80, 0x88, 0x25, 0x56, 0x26, 0x83, 0xAC}}; /* Windows.Media.Ocr.IOcrEngine */
const GUID IID_IOcrResult = {
    0x9BD235B2,
    0x175B,
    0x3D6A,
    {0x92, 0xE2, 0x38, 0x8C, 0x20, 0x6E, 0x2F, 0x63}}; /* Windows.Media.Ocr.IOcrResult */

/* IAsyncOperation<T> per-T instantiation IIDs (NOT in any winmd: computed
 * by the WinRT generic-GUID algorithm; captured from each op's GetIids at
 * runtime). QI the IAsyncInfo op for one of these to reach the
 * put_Completed(6) / get_Completed(7) / GetResults(8) view. */
const GUID IID_IAsyncOp_IRandomAccessStream = {
    0x430ECECE, 0x1418, 0x5D19, {0x81, 0xB2, 0x5D, 0xDB, 0x38, 0x16, 0x03, 0xCC}}; /* OpenAsync */
const GUID IID_IAsyncOp_BitmapDecoder = {
    0xAA94D8E9, 0xCAEF, 0x53F6, {0x82, 0x3D, 0x91, 0xB6, 0xE8, 0x34, 0x05, 0x10}}; /* CreateAsync */
const GUID IID_IAsyncOp_BitmapFrame = {
    0xCB1483D1,
    0x1464,
    0x5BF9,
    {0x93, 0x46, 0xD5, 0x37, 0x73, 0x5D, 0xFB, 0xD6}}; /* GetFrameAsync */
const GUID IID_IAsyncOp_SoftwareBitmap = {
    0xC4A10980,
    0x714B,
    0x5501,
    {0x8D, 0xA2, 0xDB, 0xDA, 0xCC, 0xE7, 0x0F, 0x73}}; /* GetSoftwareBitmapAsync */
const GUID IID_IAsyncOp_OcrResult = {
    0xC7D7118E,
    0xAE36,
    0x59C0,
    {0xAC, 0x76, 0x7B, 0xAD, 0xEE, 0x71, 0x1C, 0x8B}}; /* RecognizeAsync */

typedef struct IUnkVtbl {
    HRESULT (*QueryInterface)(void*, const GUID*, void**);
    ULONG (*AddRef)(void*);
    ULONG (*Release)(void*);
    void* iinspectable[3];
} IUnkVtbl;

/* The *Async out-param is an IAsyncInfo interface (slots 6-10 below).
 * async_wait QIs it for the per-T IAsyncOperation<T> instantiation IID,
 * where slot 6 = put_Completed and slot 8 = GetResults (reached by casting
 * the get_Id / get_ErrorCode fields). */
typedef struct IAsyncOpVtbl {
    IUnkVtbl unk;
    void* get_Id;                              /* 6 */
    HRESULT (*get_Status)(void*, int*);        /* 7 */
    HRESULT (*get_ErrorCode)(void*, HRESULT*); /* 8 */
    void* Cancel;                              /* 9 */
    void* Close;                               /* 10 */
    void* put_Progress;                        /* 11 */
    void* get_Progress;                        /* 12 */
    void* put_Completed;                       /* 13 */
    void* get_Completed;                       /* 14 */
    void* GetResults;                          /* 15 */
} IAsyncOpVtbl;
typedef struct IAsyncOp {
    const IAsyncOpVtbl* lpVtbl;
} IAsyncOp;

typedef struct IRandomAccessStream {
    const IUnkVtbl* lpVtbl;
} IRandomAccessStream;

/* IFileRandomAccessStreamStatics: [6] OpenAsync(path, accessMode) ->
 * IAsyncOperation<IRandomAccessStream> */
typedef struct IFileRandomAccessStreamStaticsVtbl {
    IUnkVtbl unk;
    HRESULT (*OpenAsync)(void*, HSTRING path, int accessMode, void** op); /* 6 */
} IFileRandomAccessStreamStaticsVtbl;
typedef struct IFileRandomAccessStreamStatics {
    const IFileRandomAccessStreamStaticsVtbl* lpVtbl;
} IFileRandomAccessStreamStatics;

/* IBitmapDecoderStatics: [14] CreateAsync(IRandomAccessStream) -> IAsyncOperation<BitmapDecoder> */
typedef struct IBitmapDecoderStaticsVtbl {
    IUnkVtbl unk;
    void* get_BmpDecoderId;
    void* get_JpegDecoderId;
    void* get_PngDecoderId;
    void* get_TiffDecoderId;
    void* get_GifDecoderId;
    void* get_JpegXRDecoderId;
    void* get_IcoDecoderId;
    void* GetDecoderInformationEnumerator;
    HRESULT (*CreateAsync)(void*, IRandomAccessStream* stream, void** op); /* 14 */
} IBitmapDecoderStaticsVtbl;
typedef struct IBitmapDecoderStatics {
    const IBitmapDecoderStaticsVtbl* lpVtbl;
} IBitmapDecoderStatics;

/* IBitmapDecoder: [10] GetFrameAsync(uint) -> IAsyncOperation<BitmapFrame> */
typedef struct IBitmapDecoderVtbl {
    IUnkVtbl unk;
    void* get_BitmapContainerProperties;
    void* get_DecoderInformation;
    void* get_FrameCount;
    void* GetPreviewAsync;
    HRESULT (*GetFrameAsync)(void*, unsigned int, void** op); /* 10 */
} IBitmapDecoderVtbl;
typedef struct IBitmapDecoder {
    const IBitmapDecoderVtbl* lpVtbl;
} IBitmapDecoder;

/* IBitmapFrameWithSoftwareBitmap: [6] GetSoftwareBitmapAsync() -> IAsyncOperation<SoftwareBitmap>
 */
typedef struct IBitmapFrameWSBVtbl {
    IUnkVtbl unk;
    HRESULT (*GetSoftwareBitmapAsync)(void*, void** op); /* 6 */
} IBitmapFrameWSBVtbl;
typedef struct IBitmapFrameWSB {
    const IBitmapFrameWSBVtbl* lpVtbl;
} IBitmapFrameWSB;

/* IOcrEngineStatics: [10] TryCreateFromUserProfileLanguages() -> OcrEngine (sync) */
typedef struct IOcrEngineStaticsVtbl {
    IUnkVtbl unk;
    void* get_MaxImageDimension;
    void* get_AvailableRecognizerLanguages;
    void* IsLanguageSupported;
    void* TryCreateFromLanguage;
    HRESULT (*TryCreateFromUserProfileLanguages)(void*, void** engine); /* 10 */
} IOcrEngineStaticsVtbl;
typedef struct IOcrEngineStatics {
    const IOcrEngineStaticsVtbl* lpVtbl;
} IOcrEngineStatics;

/* IOcrEngine: [6] RecognizeAsync(SoftwareBitmap) -> IAsyncOperation<OcrResult> */
typedef struct IOcrEngineVtbl {
    IUnkVtbl unk;
    HRESULT (*RecognizeAsync)(void*, void* softwareBitmap, void** op); /* 6 */
} IOcrEngineVtbl;
typedef struct IOcrEngine {
    const IOcrEngineVtbl* lpVtbl;
} IOcrEngine;

/* IOcrResult: [8] get_Text() -> string */
typedef struct IOcrResultVtbl {
    IUnkVtbl unk;
    void* get_Lines;
    void* get_TextAngle;
    HRESULT (*get_Text)(void*, HSTRING* text); /* 8 */
} IOcrResultVtbl;
typedef struct IOcrResult {
    const IOcrResultVtbl* lpVtbl;
} IOcrResult;

/* Run Windows.Media.Ocr over the image at `path` (wide). On success returns 0
 * and *out_utf8 is a malloc'd NUL-terminated UTF-8 string of recognized text. */
int winrt_ocr_file(const wchar_t* path, char** out_utf8);

#ifdef __cplusplus
}
#endif
#endif /* WINRT_OCR_H */