/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    AttestationAPI.h

Author:

    Stefan Thom, stefanth@Microsoft.com, 2011/06/09

Abstract:

    Definitions, types and prototypes for the internal implementation of the Attestatio API.

--*/

#ifdef _MSC_VER
#pragma once
#endif

#ifndef ATTESTATIONAPI_H
#define ATTESTATIONAPI_H

#if defined(__cplusplus)
extern "C" {
#endif

// SHA related constants
#define SHA1_DIGEST_SIZE   (20)
#define SHA256_DIGEST_SIZE (32)
#define SHA384_DIGEST_SIZE (48)
#define SHA512_DIGEST_SIZE (64)

// TPM related constants
#define AVAILABLE_PLATFORM_PCRS (24)
#define TPM12_1ST_RESETTABLE_PCR (17)
#define TPM12_NUM_RESETTABLE_PCR (6)
#define TPM12_PCR_TRUSTPOINT (-1)
#define TPM12_PCR_DETAILS (12)

// TPM12.cpp

HRESULT
GetKeyHandleFromPubKeyBlob12(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    BCRYPT_ALG_HANDLE hAlg,
    _Out_ BCRYPT_KEY_HANDLE* phPubKey,
    _Out_opt_ PUINT32 pcbTrailing
    );

HRESULT
GetKeyHandleFromKeyBlob12(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    BCRYPT_ALG_HANDLE hAlg,
    _Out_ BCRYPT_KEY_HANDLE* phPubKey,
    _Out_opt_ PUINT32 pcbTrailing
    );

HRESULT
StartOIAPSession(
    _In_ TBS_HCONTEXT hPlatformTbsHandle,
    _Out_ PUINT32 pSessionHandle,
    _Out_writes_(SHA1_DIGEST_SIZE) PBYTE pEvenNonce,
    _Out_writes_(SHA1_DIGEST_SIZE) PBYTE pOddNonce
    );

HRESULT
PubKeyFromIdBinding12(
    _In_reads_(cbIdBinding) PBYTE pbIdBinding,
    UINT32 cbIdBinding,
    BCRYPT_ALG_HANDLE hRsaAlg,
    _Out_ BCRYPT_KEY_HANDLE* phAikPub
    );

HRESULT
GenerateActivation12(
    BCRYPT_KEY_HANDLE hEkPub,
    _In_reads_(cbIdBinding) PBYTE pbIdBinding,
    UINT32 cbIdBinding,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbSecret) PBYTE pbSecret,
    UINT16 cbSecret,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

HRESULT
GenerateQuote12(
    TBS_HCONTEXT hPlatformTbsHandle,
    UINT32 hPlatformKeyHandle,
    _In_reads_(cbKeyAuth) PBYTE pbKeyAuth,
    UINT32 cbKeyAuth,
    UINT32 pcrMask,
    _In_reads_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbQuote, *pcbResult) PBYTE pbQuote,
    UINT32 cbQuote,
    _Out_ PUINT32 pcbResult
    );

HRESULT
GetPlatformPcrs12(
    TBS_HCONTEXT hPlatformTbsHandle,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

HRESULT
ValidateQuoteContext12(
    _In_reads_(cbQuote) PBYTE pbQuote,
    UINT32 cbQuote,
    _In_reads_(cbPcrList) PBYTE pbPcrList,
    UINT32 cbPcrList,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_ PUINT32 pPcrMask
    );

HRESULT
CertifyKey12(
    TBS_HCONTEXT hPlatformTbsHandle,
    UINT32 hPlatformAikHandle,
    _In_reads_opt_(cbAikUsageAuth) PBYTE pbAikUsageAuth,
    UINT32 cbAikUsageAuth,
    UINT32 hPlatformKeyHandle,
    _In_reads_opt_(cbKeyUsageAuth) PBYTE pbKeyUsageAuth,
    UINT32 cbKeyUsageAuth,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

HRESULT
ValidateKeyAttest12(
    _In_reads_(cbKeyAttest) PBYTE pbKeyAttest,
    UINT32 cbKeyAttest,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbKeyAttest) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    UINT32 pcrMask,
    _In_reads_opt_(AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE) PBYTE pcrTable
    );

HRESULT
GetKeyProperties12(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    _Out_ PUINT32 pPropertyFlags
    );

HRESULT
WrapPlatformKey12(
    _In_reads_(cbKeyPair) PBYTE pbKeyPair,
    UINT32 cbKeyPair,
    BCRYPT_KEY_HANDLE hStorageKey,
    UINT32 keyUsage,
    _In_reads_opt_(cbUsageAuth) PBYTE pbUsageAuth,
    UINT32 cbUsageAuth,
    UINT32 pcrMask,
    _In_reads_opt_(AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE) PBYTE pcrTable,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

HRESULT
GetCapability12(
	TBS_HCONTEXT hPlatformTbsHandle,
	UINT32 capArea,
	_In_reads_(cbNonce) PBYTE pbSubCap,
	UINT32 cbSubCap,
	_Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
	UINT32 cbOutput,
	_Out_ PUINT32 pcbResult
);

HRESULT
NvDefineSpace12(
	_In_ TBS_HCONTEXT hPlatformTbsHandle,
	UINT32 index,
	UINT32 indexSize,
	_In_reads_(cbOwnerAuth) PBYTE pbOwnerAuth,
	UINT32 cbOwnerAuth,
	_In_reads_(cbIndexAuth) PBYTE pbIndexAuth,
	UINT32 cbIndexAuth,
	UINT32 permissions
	);

HRESULT
CreateNvPublic(
	UINT32 nvIndex,
	UINT32 nvSize,
	UINT32 attributes,
	_Out_writes_to_opt_(cbOutput, *pSize) PBYTE pbOutput,
	UINT32 cbOutput,
	_Out_ PUINT32 pSize
);

BOOLEAN isEncryptAuthSupported(TBS_HCONTEXT hPlatformTbsHandle, UINT32 encType);

HRESULT
StartOSAPSession(
	_In_ TBS_HCONTEXT hPlatformTbsHandle,
	UINT16 entityType,
	UINT32 entityValue,
	_Out_ PUINT32 pSessionHandle,
	_Out_writes_(SHA1_DIGEST_SIZE) PBYTE pEvenNonce,
	_Out_writes_(SHA1_DIGEST_SIZE) PBYTE pOddNonce,
	_Out_writes_(SHA1_DIGEST_SIZE) PBYTE pEvenNonceOSAP,
	_Out_writes_(SHA1_DIGEST_SIZE) PBYTE pOddNonceOSAP
);

HRESULT
changeAuthOwner12(
	_In_ TBS_HCONTEXT hPlatformTbsHandle,
	_In_reads_(cbOwnerAuth) PBYTE pbOwnerAuth,
	UINT32 cbOwnerAuth
);

HRESULT
nvWriteVauleAuth12(
	TBS_HCONTEXT hPlatformTbsHandle,
	UINT32 index,
	_In_reads_(cbIndexAuth) PBYTE pbIndexAuth,
	UINT32 cbIndexAuth,
	_In_reads_(cbData) PBYTE pbData,
	UINT32 cbData
);

HRESULT
nvReadVaule12(
	TBS_HCONTEXT hPlatformTbsHandle,
	UINT32 index,
	_In_reads_(cbIndexAuth) PBYTE pbOwnerAuth,
	UINT32 cbOwnerAuth,
	_Out_writes_to_opt_(cbOutput, *pSize) PBYTE pbOutput,
	UINT32 cbOutput,
	_Out_ PUINT32 pSize
);

HRESULT
pcrExtend12(
	TBS_HCONTEXT hPlatformTbsHandle,
	UINT32 pcrIndex,
	_In_ PBYTE pbDigest,
	_Out_ PBYTE pbNewDigest
);
// TPM20.cpp
#include <tcg/tpm20/tpm20.h>

HRESULT
GetNameFromPublic(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    _Out_opt_ LPCWSTR* pNameAlg,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
);

HRESULT
GetKeyHandleFromPubKeyBlob20(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    BCRYPT_ALG_HANDLE hAlg,
    _Out_ BCRYPT_KEY_HANDLE* phPubKey,
    _Out_opt_ PUINT32 pcbTrailing,
    _Out_opt_ LPCWSTR* pSignHashAlg
);

HRESULT
PubKeyFromIdBinding20(
    _In_reads_(cbIdBinding) PBYTE pbIdBinding,
    UINT32 cbIdBinding,
    BCRYPT_ALG_HANDLE hRsaAlg,
    _Out_ BCRYPT_KEY_HANDLE* phAikPub
    );

HRESULT
AikNameFromIdBinding20(
_In_reads_(cbIdBinding) PBYTE pbIdBinding,
UINT32 cbIdBinding,
_Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
UINT32 cbOutput,
_Out_ PUINT32 pcbResult
);

HRESULT
GenerateActivation20(
    BCRYPT_KEY_HANDLE hEkPub,
    _In_reads_(cbIdBinding) PBYTE pbIdBinding,
    UINT32 cbIdBinding,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbSecret) PBYTE pbSecret,
    UINT16 cbSecret,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

HRESULT
GenerateQuote20(
    TBS_HCONTEXT hPlatformTbsHandle,
    UINT32 hPlatformKeyHandle,
    _In_reads_opt_(cbKeyAuth) PBYTE pbKeyAuth,
    UINT32 cbKeyAuth,
    UINT32 pcrMask,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbQuote, *pcbResult) PBYTE pbQuote,
    UINT32 cbQuote,
    _Out_ PUINT32 pcbResult
    );

HRESULT
GetPlatformPcrs20(
    TBS_HCONTEXT hPlatformTbsHandle,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

HRESULT
ValidateQuoteContext20(
    _In_reads_(cbQuote) PBYTE pbQuote,
    UINT32 cbQuote,
    _In_reads_(cbPcrList) PBYTE pbPcrList,
    UINT32 cbPcrList,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_ PUINT32 pPcrMask
    );

HRESULT
CertifyKey20(
    TBS_HCONTEXT hPlatformTbsHandle,
    UINT32 hPlatformAikHandle,
    _In_reads_opt_(cbAikUsageAuth) PBYTE pbAikUsageAuth,
    UINT32 cbAikUsageAuth,
    UINT32 hPlatformKeyHandle,
    _In_reads_opt_(cbKeyUsageAuth) PBYTE pbKeyUsageAuth,
    UINT32 cbKeyUsageAuth,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

HRESULT
ValidateKeyAttest20(
    _In_reads_(cbKeyAttest) PBYTE pbKeyAttest,
    UINT32 cbKeyAttest,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbKeyAttest) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    UINT32 pcrMask,
    _In_reads_opt_(AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE) PBYTE pcrTable
    );

HRESULT
GetKeyProperties20(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    _Out_opt_ PUINT32 pPropertyFlags
    );

HRESULT
WrapPlatformKey20(
    _In_reads_(cbKeyPair) PBYTE pbKeyPair,
    UINT32 cbKeyPair,
    BCRYPT_KEY_HANDLE hStorageKey,
    UINT32 keyUsage,
    _In_reads_opt_(cbUsageAuth) PBYTE pbUsageAuth,
    UINT32 cbUsageAuth,
    UINT32 pcrMask,
    _In_reads_opt_(AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE) PBYTE pcrTable,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    );

HRESULT NvDefineSpace20(
	TBS_HCONTEXT hPlatformTbsHandle,
	TPM_RH authHandle, // TPM2 Authorization 
	_In_reads_(authHandleKeySize) PCBYTE authHandleKey,
	UINT16 authHandleKeySize,
	UINT32 nvIndex,
	DWORD nvIndexAttributes,
	_In_reads_(indexKeySize) PBYTE indexKey,
	UINT16 indexKeySize,
	UINT16 dataSize);

HRESULT NvRead20(
	TBS_HCONTEXT hPlatformContextHandle,
	UINT32 authHandle,
	_In_reads_(authKeySize) PCBYTE authKey,
	UINT32 authKeySize,
	UINT32 nvIndex,
	UINT32 offset,
	_Out_writes_to_(outBufSize) PBYTE outBuf,
	UINT32 outBufSize,
	_Out_ PUINT32 actualDataSize);

HRESULT NvWrite20(
	TBS_HCONTEXT hPlatformContextHandle,
	UINT32 authHandle,
	_In_reads_(authHandleKeySize) PCBYTE authHandleKey,
	UINT32 authHandleKeySize,
	UINT32 nvIndex,
	UINT16 offset,
	_In_reads_(inBufferSize) PBYTE inBuffer,
	UINT32 inBufferSize);

HRESULT NvRelease20(
	TBS_HCONTEXT hPlatformContextHandle,
	_In_reads_(authKeySize) PCBYTE authKey,
	UINT32 authKeySize,
	UINT32 nvIndex);

#if defined(__cplusplus)
}
#endif

#endif //ATTESTATIONAPI_H
