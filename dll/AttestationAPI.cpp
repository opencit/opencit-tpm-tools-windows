/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    AttestationAPI.cpp

Author:

    Stefan Thom, stefanth@Microsoft.com, 2011/06/09

Abstract:

    API surface that offers advanced TPM functionality for attestation.

--*/

#include "stdafx.h"

// Global hash handles are kept open for performance reasons
BCRYPT_ALG_HANDLE g_hSHA1HashAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA1HmacAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA256HashAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA256HmacAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA384HashAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA384HmacAlg = NULL;

/// <summary>
///    Calculate SHA hash or HMAC.
/// </summary>
/// <param name="pszAlgId">BCrypt algorithm string.</param>
/// <param name="pbKey">pointer to Optional HMAC key.</param>
/// <param name="cbKey">size of Optional HMAC key.</param>
/// <param name="pbData">pointer to Data to be hashed.</param>
/// <param name="cbData">size of Data to be hashed.</param>
/// <param name="pbResult">Upon successful return, pointer to the digest.</param>
/// <param name="cbResult">Initial size of digest buffer.</param>
/// <param name="pcbResult">pointer to actually used size of digest buffer.</param>
/// <returns>
///    S_OK - Success.
///    E_INVALIDARG - Parameter error.
///    E_FAIL - Internal consistency error.
///    Others as propagated by called functions.
///</returns>
DllExport HRESULT TpmAttiShaHash(
    LPCWSTR pszAlgId,
    _In_reads_opt_(cbKey) PBYTE pbKey,
    UINT32 cbKey,
    _In_reads_(cbData) PBYTE pbData,
    UINT32 cbData,
    _Out_writes_to_opt_(cbResult, *pcbResult) PBYTE pbResult,
    UINT32 cbResult,
    _Out_ PUINT32 pcbResult)
{
    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE* phAlg = NULL;
    BCRYPT_ALG_HANDLE  hTempAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD dwFlags = 0;
    DWORD hashSize = 0;
    DWORD cbHashSize = 0;

    if((cbKey == 0) || (pbKey == NULL))
    {
        if(wcscmp(pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA1HashAlg;
        }
        else if(wcscmp(pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA256HashAlg;
        }
        else if(wcscmp(pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA384HashAlg;
        }
        else
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
    }
    else
    {
        if(wcscmp(pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA1HmacAlg;
        }
        else if(wcscmp(pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA256HmacAlg;
        }
        else if(wcscmp(pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA384HmacAlg;
        }
        else
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        dwFlags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
    }

    // Open the provider if not already open
    if(*phAlg == NULL)
    {
        if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                    &hTempAlg,
                                    pszAlgId,
                                    MS_PRIMITIVE_PROVIDER,
                                    dwFlags))))
        {
            goto Cleanup;
        }
        if(InterlockedCompareExchangePointer((volatile PVOID *) phAlg, (PVOID)hTempAlg, NULL) != NULL)
        {
            BCryptCloseAlgorithmProvider(hTempAlg, 0);
        }
    }

    // Check output buffer size
    if(FAILED(hr = HRESULT_FROM_NT(BCryptGetProperty(
                              *phAlg,
                              BCRYPT_HASH_LENGTH,
                              (PUCHAR)&hashSize,
                              sizeof(hashSize),
                              &cbHashSize,
                              0))))
    {
        goto Cleanup;
    }

    // Size check?
    if((pbResult == NULL) || (cbResult == 0))
    {
        *pcbResult = hashSize;
        goto Cleanup;
    }
    else if(cbResult < hashSize)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = hashSize;
        goto Cleanup;
    }

    // Create the hash
    if(FAILED(hr = HRESULT_FROM_NT(BCryptCreateHash(
                              *phAlg,
                              &hHash,
                              NULL,
                              0,
                              pbKey,
                              (ULONG)cbKey,
                              0))))
    {
        goto Cleanup;
    }

    // Hash the data
    if(FAILED(hr = HRESULT_FROM_NT(BCryptHashData(
                            hHash,
                            pbData,
                            (ULONG)cbData,
                            0))))
    {
        goto Cleanup;
    }

    // Calculate the digesst
    if(FAILED(hr = HRESULT_FROM_NT(BCryptFinishHash(
                              hHash,
                              pbResult,
                              (ULONG)cbResult,
                              0))))
    {
        goto Cleanup;
    }
    *pcbResult = hashSize;

Cleanup:
    if(hHash != NULL)
    {
        BCryptDestroyHash(hHash);
        hHash = NULL;
    }
    return hr;
}

/// <summary>
/// Realease all hash providers.
/// </summary>
DllExport void TpmAttiReleaseHashProviders(
    )
{
    if(g_hSHA1HashAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hSHA1HashAlg, 0);
        g_hSHA1HashAlg = NULL;
    }
    if(g_hSHA1HmacAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hSHA1HmacAlg, 0);
        g_hSHA1HmacAlg = NULL;
    }
    if(g_hSHA256HashAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hSHA256HashAlg, 0);
        g_hSHA256HashAlg = NULL;
    }
    if(g_hSHA256HmacAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hSHA256HmacAlg, 0);
        g_hSHA256HmacAlg = NULL;
    }
    if(g_hSHA384HashAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hSHA384HashAlg, 0);
        g_hSHA384HashAlg = NULL;
    }
    if(g_hSHA384HmacAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hSHA384HmacAlg, 0);
        g_hSHA384HmacAlg = NULL;
    }
}

/*++

Routine Description:

    Obtain the TPM version of the platform.

Arguments:

    pTpmVersion - Pointer to variable that will receive TPM version

Return value:

    S_OK - Success.

    E_INVALIDARG - Parameter error.

    E_FAIL - Internal consistency error.

    Others as propagated by called functions.

--*/


/// <summary>
/// Obtain the TPM version of the platform.
/// </summary>
/// <param name="pTpmVersion">Pointer to variable that will receive TPM version</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttiGetTpmVersion(
    _Out_ PUINT32 pTpmVersion
    )
{
    HRESULT hr = S_OK;
    TPM_DEVICE_INFO info = {0};

    if(pTpmVersion == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    if(FAILED(hr = Tbsi_GetDeviceInfo(sizeof(info), (PVOID)&info)))
    {
        goto Cleanup;
    }

    *pTpmVersion = info.tpmVersion;

Cleanup:
    return hr;
}

/// <summary>
/// Calculate a bank of SHA-1 PCRs from a given TCG log.
/// </summary>
/// <param name="pbEventLog">pointer to EventLog to be parsed.</param>
/// <param name="cbEventLog">size of EventLog to be parsed.</param>
/// <param name="pbSwPcr">Pointer to PCR bank.</param>
/// <param name="pPcrMask">PCR mask that will indicate for which PCRs were log entries present</param>
/// <returns>
/// S_OK - Success.
/// E_INVALIDARG - Parameter error.
/// E_FAIL - Internal consistency error.
/// Others as propagated by called functions.
/// </returns>
HRESULT TpmAttiComputeSoftPCRs(
    _In_reads_(cbEventLog) PBYTE pbEventLog,
    UINT32 cbEventLog,
    _Out_writes_(AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE) PBYTE pbSwPcr,
    _Out_opt_ PUINT32 pPcrMask)
{
    HRESULT hr = S_OK;
    PTCG_PCClientPCREventStruct pEntry = NULL;
    BYTE digestBuffer[SHA1_DIGEST_SIZE * 2];
    UINT32 cbDigestSize = 0;
    UINT32 pcrMask = 0;

    // Check parameters
    if((pbEventLog == NULL) ||
       (cbEventLog == 0) ||
       (pbSwPcr == NULL))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Initialize PCRs
    memset(pbSwPcr, 0x00, AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE);
    // According to the TPM spec all resettable PCRs have to be reset to 0xff.
    // "What about PCR[16, 23]?" you ask - Well the TIS spec says that they
    // have to be initialized to 0. For people that love ambiguity this is a
    // perfect world and to make things sweeter, ATMEL prefers to agree with
    // the TPM main spec, while everyone else feels that the TIS spec is the
    // way to go.
    // But to put things into perspective: Nobody should really care for
    // PCR[16-13] and so we go with the majority of people that agree with
    // the TIS spec on an issue that is almost entirely irrelevant.
    memset(&pbSwPcr[TPM12_1ST_RESETTABLE_PCR * SHA1_DIGEST_SIZE],
           0xff,
           SHA1_DIGEST_SIZE * TPM12_NUM_RESETTABLE_PCR);

    // Parse the log
    for(pEntry = (PTCG_PCClientPCREventStruct)pbEventLog;
        ((PBYTE)pEntry - pbEventLog + sizeof(TCG_PCClientPCREventStruct) -
                                sizeof(BYTE)) < cbEventLog;
        pEntry = (PTCG_PCClientPCREventStruct) (((PBYTE)pEntry) +
                           sizeof(TCG_PCClientPCREventStruct) -
                           sizeof(BYTE) +
                           pEntry->eventDataSize))
    {
        UINT32 cbEntry = sizeof(TCG_PCClientPCREventStruct) -
                         sizeof(BYTE) +
                         pEntry->eventDataSize;

        // Make sure that the entry is completely inside the log buffer
        if(((PBYTE)pEntry - pbEventLog + cbEntry) > cbEventLog)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        // Make sure that we have a proper PCRindex otherwise ignore it
        if(pEntry->pcrIndex >= AVAILABLE_PLATFORM_PCRS)
        {
            continue;
        }

        // Non-extended event, ignore it
        if(pEntry->eventType == SIPAEV_NO_ACTION)
        {
            continue;
        }

        // Prepare the hash buffer
        if(memcpy_s(digestBuffer,
                    sizeof(digestBuffer),
                    &pbSwPcr[pEntry->pcrIndex * SHA1_DIGEST_SIZE],
                    SHA1_DIGEST_SIZE))
        {
            hr = E_FAIL;
            goto Cleanup;
        }
        if(memcpy_s(&digestBuffer[SHA1_DIGEST_SIZE],
                    sizeof(digestBuffer) - SHA1_DIGEST_SIZE,
                    pEntry->digest.data,
                    SHA1_DIGEST_SIZE))
        {
            hr = E_FAIL;
            goto Cleanup;
        }

        // Perform the extend
        if(FAILED(hr = TpmAttiShaHash(
                            BCRYPT_SHA1_ALGORITHM,
                            NULL,
                            0,
                            digestBuffer,
                            sizeof(digestBuffer),
                            &pbSwPcr[pEntry->pcrIndex * SHA1_DIGEST_SIZE],
                            SHA1_DIGEST_SIZE,
                            &cbDigestSize)))
        {
            goto Cleanup;
        }

        // Mark the pcrMask
        pcrMask |= (0x00000001 << pEntry->pcrIndex);
    }

    // Return the mask if requested
    if(pPcrMask != NULL)
    {
        *pPcrMask = pcrMask;
    }

Cleanup:
    return hr;
}

/// <summary>
/// Filter eventlog to contain only entries that are specified in the PCRMask.
/// </summary>
/// <param name="pbEventLog">pointer to EventLog to be filtered.</param>
/// <param name="cbEventLog">size of EventLog to be filtered.</param>
/// <param name="pcrMask">filter mask.</param>
/// <param name="pbOutput">Upon successful return, contains the digest</param>
/// <param name="cbOutput">input size of the digest buffer</param>
/// <param name="pcbResult">output size of the digest buffer</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
HRESULT TpmAttiFilterLog(
    _In_reads_(cbEventLog) PBYTE pbEventLog,
    UINT32 cbEventLog,
    UINT32 pcrMask,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    )
{
    HRESULT hr = S_OK;
    PTCG_PCClientPCREventStruct pEntry = NULL;
    ULONG cbTargetLog = 0;
    ULONG cbOutputIndex = 0;

    // Parameter checking
    if((pbEventLog == NULL) ||
       (cbEventLog < sizeof(TCG_PCClientPCREventStruct)) ||
       (pcrMask == 0) ||
       (pcbResult == NULL))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Make OACR happy
    *pcbResult = 0;

    // 1st pass to find out how much space we will need
    for(pEntry = (PTCG_PCClientPCREventStruct)pbEventLog;
        ((PBYTE)pEntry - pbEventLog + sizeof(TCG_PCClientPCREventStruct) -
                                sizeof(BYTE)) < cbEventLog;
        pEntry = (PTCG_PCClientPCREventStruct) (((PBYTE)pEntry) +
                           sizeof(TCG_PCClientPCREventStruct) -
                           sizeof(BYTE) +
                           pEntry->eventDataSize))
    {
        ULONG cbEntry = sizeof(TCG_PCClientPCREventStruct) -
                        sizeof(BYTE) +
                        pEntry->eventDataSize;

        // Make sure that we have a proper PCRindex, if not ignore entry
        if((pEntry->pcrIndex > AVAILABLE_PLATFORM_PCRS) ||
           (((PBYTE)pEntry - pbEventLog + cbEntry) > cbEventLog))
        {
            continue;
        }

        // Apply the filter
        if(((0x00000001 << pEntry->pcrIndex) & pcrMask) != 0)
        {
            // We want to keep this entry
            cbTargetLog += sizeof(TCG_PCClientPCREventStruct) -
                           sizeof(BYTE) +
                           pEntry->eventDataSize;
        }
    }

    // Return the attestation data
    if((pbOutput == NULL) || (cbOutput == 0))
    {
        *pcbResult = cbTargetLog;
        goto Cleanup;
    }
    else if(cbOutput < cbTargetLog)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = cbTargetLog;
        goto Cleanup;
    }

    // 2nd pass to copy the entries
    for(pEntry = (PTCG_PCClientPCREventStruct)pbEventLog;
        ((PBYTE)pEntry - pbEventLog + sizeof(TCG_PCClientPCREventStruct) -
                            sizeof(BYTE)) < cbEventLog;
        pEntry = (PTCG_PCClientPCREventStruct) (((PBYTE)pEntry) +
                            sizeof(TCG_PCClientPCREventStruct) -
                            sizeof(BYTE) +
                            pEntry->eventDataSize))
    {
        ULONG cbEntry = sizeof(TCG_PCClientPCREventStruct) -
                        sizeof(BYTE) +
                        pEntry->eventDataSize;

        // Make sure that we have a proper PCRindex, if not ignore entry
        if((pEntry->pcrIndex > AVAILABLE_PLATFORM_PCRS) ||
            (((PBYTE)pEntry - pbEventLog + cbEntry) > cbEventLog))
        {
            continue;
        }

        // Apply the filter
        if(((0x00000001 << pEntry->pcrIndex) & pcrMask) != 0)
        {
            // Sanity check: Does this entry still fit?
            if((cbOutputIndex + cbEntry) > cbOutput)
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }

            // Copy the entry
            if(memcpy_s(&pbOutput[cbOutputIndex], cbOutput - cbOutputIndex, (PBYTE)pEntry, cbEntry))
            {
                hr = E_FAIL;
                goto Cleanup;
            }
            cbOutputIndex += cbEntry;
        }
    }

    // Return final size
    *pcbResult = cbTargetLog;

Cleanup:
    return hr;
}

/// <summary>
/// Retrieve BCrypt key handle from IDBinding. This function is typically called on a server.
/// </summary>
/// <param name="pbIdBinding">pointer to IDBinding from Client.</param>
/// <param name="cbIdBinding">size of IDBinding from Client.</param>
/// <param name="hRsaAlg">Provider handle in which the handle should be opened.</param>
/// <param name="phAikPub">Upon successful return, contains handle to key</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttPubKeyFromIdBinding(
    _In_reads_(cbIdBinding) PBYTE pbIdBinding,
    UINT32 cbIdBinding,
    BCRYPT_ALG_HANDLE hRsaAlg,
    _Out_ BCRYPT_KEY_HANDLE* phAikPub
    )
{
    HRESULT hr = S_OK;
    const BYTE IdBindingTag12[] = {0x01, 0x01, 0x00, 0x00};
    const BYTE IdBindingTag20[] = {0x00, 0x01};

    // Identify if this is a 1.2 or 2.0 activation blob
    if(memcmp(pbIdBinding, IdBindingTag12, sizeof(IdBindingTag12)) == 0)
    {
        if(FAILED(hr = PubKeyFromIdBinding12(pbIdBinding,
                                             cbIdBinding,
                                             hRsaAlg,
                                             phAikPub)))
        {
            goto Cleanup;
        }
    }
    else if(memcmp(&pbIdBinding[0x02], IdBindingTag20, sizeof(IdBindingTag20)) == 0)
    {
        if(FAILED(hr = PubKeyFromIdBinding20(pbIdBinding,
                                             cbIdBinding,
                                             hRsaAlg,
                                             phAikPub)))
        {
            goto Cleanup;
        }
    }
    else
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

Cleanup:
    return hr;
}

/// <summary>
/// Generate Activation Blob from IDBinding, with a given secret. If a nonce is provided,
/// it will be validated with the nonce in the IDBinding
/// </summary>
/// <param name="hEkPub">Public key to encrypt the activation.</param>
/// <param name="pbIdBinding">pointer to IDBinding from the client.</param>
/// <param name="cbIdBinding">size of IDBinding from the client.</param>
/// <param name="pbNonce">pointer to Nonce provided to the client for key creation.</param>
/// <param name="cbNonce">size of Nonce provided to the client for key creation.</param>
/// <param name="pbSecret">pointer to Secret to be wrapped in activation.</param>
/// <param name="cbSecret">size of Secret to be wrapped in activation.</param>
/// <param name="pbOutput">Upon successful return, contains the activation blob.</param>
/// <param name="cbOutput">input size of activation blob</param>
/// <param name="pcbResult">output size of activation blob.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGenerateActivation(
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
    )
{
    HRESULT hr = S_OK;
    const BYTE IdBindingTag12[] = {0x01, 0x01, 0x00, 0x00};
    const BYTE IdBindingTag20[] = {0x00, 0x01};

    // Identify if this is a 1.2 or 2.0 activation blob
    if(memcmp(pbIdBinding, IdBindingTag12, sizeof(IdBindingTag12)) == 0)
    {
        const BYTE nullBuffer[SHA1_DIGEST_SIZE] = {0};
        if(FAILED(hr = GenerateActivation12(
                                hEkPub,
                                pbIdBinding,
                                cbIdBinding,
                                (pbNonce) ? pbNonce : (PBYTE)nullBuffer,
                                (pbNonce) ? cbNonce : sizeof(nullBuffer),
                                pbSecret,
                                cbSecret,
                                pbOutput,
                                cbOutput,
                                pcbResult)))
        {
            goto Cleanup;
        }
    }
    else if(memcmp(&pbIdBinding[0x02], IdBindingTag20, sizeof(IdBindingTag20)) == 0)
    {
        if(FAILED(hr = GenerateActivation20(
                                hEkPub,
                                pbIdBinding,
                                cbIdBinding,
                                pbNonce,
                                cbNonce,
                                pbSecret,
                                cbSecret,
                                pbOutput,
                                cbOutput,
                                pcbResult)))
        {
            goto Cleanup;
        }
    }
    else
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

Cleanup:
    return hr;
}

/// <summary>
/// Generate platform attestation blob with provided AIK over the PCRs indicated and an optional nonce
/// </summary>
/// <param name="hAik">AIK key handle, fully authorized if required.</param>
/// <param name="pcrMask">Filter for events.</param>
/// <param name="pbNonce">pointer to Nonce provided to be included in signature.</param>
/// <param name="cbNonce">size of Nonce provided to be included in signature.</param>
/// <param name="pbOutput">Upon successful return, contains the attestation blob.</param>
/// <param name="cbOutput">input size of attestation blob buffer.</param>
/// <param name="pcbResult">output size of attestation blob.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGeneratePlatformAttestation(
    NCRYPT_KEY_HANDLE hAik,
    UINT32 pcrMask,
    _In_reads_opt_ (cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    )
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    BOOLEAN tSignedAttestation = FALSE;
    UINT32 tpmVersion = 0;
    TBS_HCONTEXT hPlatformTbsHandle = 0;
    UINT32 hPlatformKeyHandle = 0;
    BYTE tUsageAuthRequired = 0;
    BYTE usageAuth[SHA1_DIGEST_SIZE] = {0};
    UINT32 cbRequired = 0;
    UINT32 cbPcrs = AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE;
    UINT32 cbQuote = 0;
    UINT32 cbSignature = 0;
    PBYTE pbLog = NULL;
    UINT32 cbLog = 0;
    UINT32 cbFilteredLog = 0;
    PPCP_PLATFORM_ATTESTATION_BLOB pAttestationBlob = (PPCP_PLATFORM_ATTESTATION_BLOB)pbOutput;
    UINT32 cursor = 0;

    // Check the parameters
    if(pcbResult == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    *pcbResult = 0;

    // Is this a signed attestation?
    if(hAik != NULL)
    {
        tSignedAttestation = TRUE;
    }

    // Get TPM version to select implementation
    if(FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
    {
        goto Cleanup;
    }

    // Obtain specific key information from the provider
    if(tSignedAttestation != FALSE)
    {
        // Obtain the provider handle from the key so we can get to the TBS handle
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hAik,
                                            NCRYPT_PROVIDER_HANDLE_PROPERTY,
                                            (PUCHAR)&hProv,
                                            sizeof(hProv),
                                            (PULONG)&cbRequired,
                                            0))))
        {
            goto Cleanup;
        }

        // Obtain the TBS handle that has been used to load the AIK
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hProv,
                                            NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
                                            (PUCHAR)&hPlatformTbsHandle,
                                            sizeof(hPlatformTbsHandle),
                                            (PULONG)&cbRequired,
                                            0))))
        {
            goto Cleanup;
        }

        // Obtain the virtualized TPM key handle that is used by the provider
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hAik,
                                            NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
                                            (PUCHAR)&hPlatformKeyHandle,
                                            sizeof(hPlatformKeyHandle),
                                            (PULONG)&cbRequired,
                                            0))))
        {
            goto Cleanup;
        }

        // Obtain the size of the signature from this key
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hAik,
                                            BCRYPT_SIGNATURE_LENGTH,
                                            (PUCHAR)&cbSignature,
                                            sizeof(cbSignature),
                                            (PULONG)&cbRequired,
                                            0))))
        {
            goto Cleanup;
        }
        // Does the key need authorization?
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hAik,
                                            NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY,
                                            (PUCHAR)&tUsageAuthRequired,
                                            sizeof(tUsageAuthRequired),
                                            (PULONG)&cbRequired,
                                            0))))
        {
            goto Cleanup;
        }

        if(tUsageAuthRequired != FALSE)
        {
            // Get the usageAuth from the provider
            if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                                hAik,
                                                NCRYPT_PCP_USAGEAUTH_PROPERTY,
                                                usageAuth,
                                                sizeof(usageAuth),
                                                (PULONG)&cbRequired,
                                                0))))
            {
                goto Cleanup;
            }
        }
    }
    else
    {
        // If we dont have a key we need to open a TBS session to read the PCRs
        TBS_CONTEXT_PARAMS2 contextParams;
        contextParams.version = TBS_CONTEXT_VERSION_TWO;
        contextParams.asUINT32 = 0;
        contextParams.includeTpm12 = 1;
        contextParams.includeTpm20 = 1;
        if(FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
        {
            goto Cleanup;
        }
    }

    // Get the event log from the system
    if(FAILED(hr = Tbsi_Get_TCG_Log(hPlatformTbsHandle, NULL, &cbLog)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbLog, cbLog)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = Tbsi_Get_TCG_Log(hPlatformTbsHandle, pbLog, &cbLog)))
    {
        goto Cleanup;
    }

    // Filter the log to the relevant entries
    if(FAILED(hr = TpmAttiFilterLog(pbLog, cbLog, pcrMask, NULL, 0, &cbFilteredLog)))
    {
        goto Cleanup;
    }

    // Quote size check for signed attestation
    if(tSignedAttestation != FALSE)
    {
        if(tpmVersion == TPM_VERSION_12)
        {
            const BYTE nullBuffer[SHA1_DIGEST_SIZE] = {0};

            // Get the quote Size
            if(FAILED(hr = GenerateQuote12(
                                    hPlatformTbsHandle,
                                    hPlatformKeyHandle,
                                    usageAuth,
                                    sizeof(usageAuth),
                                    pcrMask,
                                    (pbNonce) ? pbNonce : (PBYTE)nullBuffer,
                                    (pbNonce) ? cbNonce : sizeof(nullBuffer),
                                    NULL,
                                    0,
                                    &cbQuote)))
            {
                goto Cleanup;
            }
        }
        else if(tpmVersion == TPM_VERSION_20)
        {
            if(FAILED(hr = GenerateQuote20(
                                        hPlatformTbsHandle,
                                        hPlatformKeyHandle,
                                        (tUsageAuthRequired) ? usageAuth : NULL,
                                        (tUsageAuthRequired) ? sizeof(usageAuth) : 0,
                                        pcrMask,
                                        pbNonce,
                                        cbNonce,
                                        NULL,
                                        0,
                                        &cbQuote)))
            {
                goto Cleanup;
            }
        }
        else
        {
            hr = E_FAIL;
            goto Cleanup;
        }
    }

    // Calculate output buffer
    cbRequired = sizeof(PCP_PLATFORM_ATTESTATION_BLOB) +
                 AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE +
                 cbQuote - cbSignature +
                 cbSignature +
                 cbFilteredLog;
    if((pbOutput == NULL) || (cbOutput == 0))
    {
        *pcbResult = cbRequired;
        goto Cleanup;
    }
    if(cbOutput < cbRequired)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    // Create the output structure
    pAttestationBlob->Magic = PCP_PLATFORM_ATTESTATION_MAGIC;
    pAttestationBlob->Platform = tpmVersion;
    pAttestationBlob->HeaderSize = sizeof(PCP_PLATFORM_ATTESTATION_BLOB);
    pAttestationBlob->cbPcrValues = cbPcrs;
    pAttestationBlob->cbQuote = cbQuote - cbSignature;
    pAttestationBlob->cbSignature = cbSignature;
    pAttestationBlob->cbLog = cbFilteredLog;
    cursor = pAttestationBlob->HeaderSize;

    // Perform platform attestation and obtain the PCRs
    if(tpmVersion == TPM_VERSION_12)
    {
        const BYTE nullBuffer[SHA1_DIGEST_SIZE] = {0};

        // Get the PCRs
        if(FAILED(hr = GetPlatformPcrs12(
                            hPlatformTbsHandle,
                            &pbOutput[cursor],
                            pAttestationBlob->cbPcrValues,
                            &cbRequired)))
        {
            goto Cleanup;
        }
        cursor += cbRequired;

        // Make OACR happy
        if((cursor + pAttestationBlob->cbQuote + pAttestationBlob->cbSignature) > cbOutput)
        {
            hr = E_FAIL;
            goto Cleanup;
        }

        // Quote for signed attestation
        if(tSignedAttestation != FALSE)
        {
            if(FAILED(hr = GenerateQuote12(
                                hPlatformTbsHandle,
                                hPlatformKeyHandle,
                                usageAuth,
                                sizeof(usageAuth),
                                pcrMask,
                                (pbNonce) ? pbNonce : (PBYTE)nullBuffer,
                                (pbNonce) ? cbNonce : sizeof(nullBuffer),
                                &pbOutput[cursor],
                                pAttestationBlob->cbQuote + pAttestationBlob->cbSignature,
                                &cbRequired)))
            {
                goto Cleanup;
            }
            cursor += cbRequired;
        }
    }
    else if(tpmVersion == TPM_VERSION_20)
    {
        // Get the PCRs
        if(FAILED(hr = GetPlatformPcrs20(
                            hPlatformTbsHandle,
                            &pbOutput[cursor],
                            pAttestationBlob->cbPcrValues,
                            &cbRequired)))
        {
            goto Cleanup;
        }
        cursor += cbRequired;

        // Make OACR happy
        if((cursor + pAttestationBlob->cbQuote + pAttestationBlob->cbSignature) > cbOutput)
        {
            hr = E_FAIL;
            goto Cleanup;
        }

        // Quote for signed attestation
        if(tSignedAttestation != FALSE)
        {
            if(FAILED(hr = GenerateQuote20(
                                hPlatformTbsHandle,
                                hPlatformKeyHandle,
                                (tUsageAuthRequired) ? usageAuth : NULL,
                                (tUsageAuthRequired) ? sizeof(usageAuth) : 0,
                                pcrMask,
                                pbNonce,
                                cbNonce,
                                &pbOutput[cursor],
                                pAttestationBlob->cbQuote + pAttestationBlob->cbSignature,
                                &cbRequired)))
            {
                goto Cleanup;
            }
            cursor += cbRequired;
        }
    }
    else
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Make OACR happy
    if((cursor + pAttestationBlob->cbLog) > cbOutput)
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Get the log
    if(FAILED(hr = TpmAttiFilterLog(pbLog, cbLog, pcrMask, &pbOutput[cursor], pAttestationBlob->cbLog, &cbRequired)))
    {
        goto Cleanup;
    }
    cursor += cbRequired;

    // Return the final size
    *pcbResult = cursor;

Cleanup:
    // Close the TBS handle if we opened it in here
    if((tSignedAttestation == FALSE) && (hPlatformTbsHandle != NULL))
    {
        Tbsip_Context_Close(hPlatformTbsHandle);
        hPlatformTbsHandle = NULL;
    }
    ZeroAndFree((PVOID*)&pbLog, cbLog);
    return hr;
}

/// <summary>
/// Read and return all platform counters
/// </summary>
/// <param name="pOsBootCount">OS Boot counter - insecure index for log files.</param>
/// <param name="pOsResumeCount">OS Resume counter - insecure index for log files.</param>
/// <param name="pCurrentTpmBootCount">TPM 2.0 backed counter, not available on 1.2.</param>
/// <param name="pCurrentTpmEventCount">TPM backed monotonic counter.</param>
/// <param name="pCurrentTpmCounterId">Counter ID on 1.2 TPMs.</param>
/// <param name="pInitialTpmBootCount">TPM 2.0 backed counter, not available on 1.2 when the platform was booted.</param>
/// <param name="pInitialTpmEventCount">TPM backed monotonic counter when the platform was booted.</param>
/// <param name="pInitialTpmCounterId">Counter ID on 1.2 TPMs when the platform was booted.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGetPlatformCounters(
    _Out_opt_ PUINT32 pOsBootCount,
    _Out_opt_ PUINT32 pOsResumeCount,
    _Out_opt_ PUINT64 pCurrentTpmBootCount,
    _Out_opt_ PUINT64 pCurrentTpmEventCount,
    _Out_opt_ PUINT64 pCurrentTpmCounterId,
    _Out_opt_ PUINT64 pInitialTpmBootCount,
    _Out_opt_ PUINT64 pInitialTpmEventCount,
    _Out_opt_ PUINT64 pInitialTpmCounterId)
{
    HRESULT hr = S_OK;
    DWORD cbData = 0;

    if(pOsBootCount != NULL)
    {
        // Obtain the current OSBootCount
        cbData = sizeof(UINT32);
        if(FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
                                                HKEY_LOCAL_MACHINE,
                                                TPM_STATIC_CONFIG_DATA,
                                                L"OsBootCount",
                                                RRF_RT_REG_DWORD,
                                                NULL,
                                                (PBYTE)pOsBootCount,
                                                &cbData))))
        {
            goto Cleanup;
        }
    }

    if(pOsResumeCount != NULL)
    {
        // Obtain the current OSResumeCount
        cbData = sizeof(UINT32);
        if(FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
                                                HKEY_LOCAL_MACHINE,
                                                TPM_VOLATILE_CONFIG_DATA,
                                                L"OsResumeCount",
                                                RRF_RT_REG_DWORD,
                                                NULL,
                                                (PBYTE)pOsResumeCount,
                                                &cbData))))
        {
            goto Cleanup;
        }
    }

    if(pCurrentTpmBootCount != NULL)
    {
        // Obtain the current BootCount
        cbData = sizeof(UINT64);
        if(FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
                                                HKEY_LOCAL_MACHINE,
                                                TPM_VOLATILE_CONFIG_DATA,
                                                L"BootCount",
                                                RRF_RT_REG_QWORD,
                                                NULL,
                                                (PBYTE)pCurrentTpmBootCount,
                                                &cbData))))
        {
            goto Cleanup;
        }
    }

    if(pCurrentTpmEventCount != NULL)
    {
        // Obtain the current EventCount
        cbData = sizeof(UINT64);
        if(FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
                                                HKEY_LOCAL_MACHINE,
                                                TPM_VOLATILE_CONFIG_DATA,
                                                L"EventCount",
                                                RRF_RT_REG_QWORD,
                                                NULL,
                                                (PBYTE)pCurrentTpmEventCount,
                                                &cbData))))
        {
            goto Cleanup;
        }
    }

    if(pCurrentTpmCounterId != NULL)
    {
        // Obtain the current CounterId
        cbData = sizeof(UINT64);
        if(FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
                                                HKEY_LOCAL_MACHINE,
                                                TPM_VOLATILE_CONFIG_DATA,
                                                L"CounterId",
                                                RRF_RT_REG_QWORD,
                                                NULL,
                                                (PBYTE)pCurrentTpmCounterId,
                                                &cbData))))
        {
            goto Cleanup;
        }
    }

    if(pInitialTpmBootCount != NULL)
    {
        // Obtain the current BootCount
        cbData = sizeof(UINT64);
        if(FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
                                                HKEY_LOCAL_MACHINE,
                                                TPM_VOLATILE_CONFIG_DATA,
                                                L"InitialBootCount",
                                                RRF_RT_REG_QWORD,
                                                NULL,
                                                (PBYTE)pInitialTpmBootCount,
                                                &cbData))))
        {
            goto Cleanup;
        }
    }

    if(pInitialTpmEventCount != NULL)
    {
        // Obtain the current EventCount
        cbData = sizeof(UINT64);
        if(FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
                                                HKEY_LOCAL_MACHINE,
                                                TPM_VOLATILE_CONFIG_DATA,
                                                L"InitialEventCount",
                                                RRF_RT_REG_QWORD,
                                                NULL,
                                                (PBYTE)pInitialTpmEventCount,
                                                &cbData))))
        {
            goto Cleanup;
        }
    }

    if(pInitialTpmCounterId != NULL)
    {
        // Obtain the current CounterId
        cbData = sizeof(UINT64);
        if(FAILED(hr = HRESULT_FROM_WIN32(RegGetValueW(
                                                HKEY_LOCAL_MACHINE,
                                                TPM_VOLATILE_CONFIG_DATA,
                                                L"InitialCounterId",
                                                RRF_RT_REG_QWORD,
                                                NULL,
                                                (PBYTE)pInitialTpmCounterId,
                                                &cbData))))
        {
            goto Cleanup;
        }
    }

Cleanup:
    return hr;
}

/// <summary>
/// Obtain a log from the archive on the disk. The log is selected by the OS boot and resume counter
/// </summary>
/// <param name="OsBootCount">Selector for boot index</param>
/// <param name="OsResumeCount">Selector for resume index</param>
/// <param name="pbOutput">Upon successful return, contains the requested log.</param>
/// <param name="cbOutput">input size of log buffer</param>
/// <param name="pcbResult">output size of log buffer</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGetPlatformLogFromArchive(
    UINT32 OsBootCount,
    UINT32 OsResumeCount,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    )
{
    HRESULT hr = S_OK;
    PWSTR szWindows = NULL;
    WCHAR szLogFileName[MAX_PATH] = L"";
    HANDLE hLogFileHandle = INVALID_HANDLE_VALUE;

    // Check the parameters
    if(pcbResult == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    *pcbResult = 0;

    // Get the Windows directory
    if(FAILED(hr = SHGetKnownFolderPath(FOLDERID_Windows,
                                        0,
                                        NULL,
                                        &szWindows)))
    {
        goto Cleanup;
    }

    // Generate the desired log file name
    if(FAILED(hr = StringCchPrintfW(szLogFileName,
                                    ARRAYSIZE(szLogFileName),
                                    L"%s\\Logs\\MeasuredBoot\\%010u-%010u.log",
                                    szWindows,
                                    OsBootCount,
                                    OsResumeCount)))
    {
        goto Cleanup;
    }

    // Open the logfile on the disk
    if((hLogFileHandle = CreateFile(szLogFileName,
                                    GENERIC_READ,
                                    FILE_SHARE_READ,
                                    NULL,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    NULL)) == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Retrieve the size information
    if((*pcbResult = GetFileSize(hLogFileHandle, NULL)) == INVALID_FILE_SIZE)
    {
        *pcbResult = 0;
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Return log content
    if((pbOutput == NULL) || (cbOutput == 0))
    {
        goto Cleanup;
    }
    else if(cbOutput < *pcbResult)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        goto Cleanup;
    }
    else
    {
        if(!ReadFile(hLogFileHandle,
                     pbOutput,
                     *pcbResult,
                     NULL,
                     NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
    }

Cleanup:
    if(szWindows != NULL)
    {
        CoTaskMemFree(szWindows);
        szWindows = NULL;
    }
    if(hLogFileHandle != NULL)
    {
        CloseHandle(hLogFileHandle);
        hLogFileHandle = NULL;
    }

    return hr;
}

/// <summary>
/// Integrity verification of a platform attestation. This operation is typically done on a server.
/// </summary>
/// <param name="hAik">AIKPub handle for signature validation</param>
/// <param name="pbNonce">Optional nonce verification that was provided by the server to ensure that the attestation is fresh.</param>
/// <param name="cbNonce">size of optional nonce.</param>
/// <param name="pbAttestation">pointer to Attestation blob</param>
/// <param name="cbAttestation">size of Attestation blob</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttValidatePlatformAttestation(
    BCRYPT_KEY_HANDLE hAik,
    _In_reads_opt_ (cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_ (cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation
    )
{
    HRESULT hr = S_OK;
    PPCP_PLATFORM_ATTESTATION_BLOB pAttestation = (PPCP_PLATFORM_ATTESTATION_BLOB)pbAttestation;
    UINT32 cursor = 0;
    PBYTE pbPcrValues = NULL;
    UINT32 cbPcrValues = 0;
    PBYTE pbQuote = NULL;
    UINT32 cbQuote = 0;
    PBYTE pbSignature = NULL;
    UINT32 cbSignature = 0;
    PBYTE pbLog = NULL;
    UINT32 cbLog = 0;
    BYTE quoteDigest[SHA1_DIGEST_SIZE] = {0};
    UINT32 cbQuoteDigest = 0;
    BCRYPT_PKCS1_PADDING_INFO pPkcs = {BCRYPT_SHA1_ALGORITHM};
    UINT32 pcrMask = 0;
    UINT32 pcrMaskLog = 0;
    BYTE softwarePCR[AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE] = {0};
    TBS_HCONTEXT hPlatformTbsHandle = 0;

    // Check the parameters
    if((pbAttestation == NULL) ||
       (cbAttestation < sizeof(PCP_PLATFORM_ATTESTATION_BLOB)) ||
       (pAttestation->Magic != PCP_PLATFORM_ATTESTATION_MAGIC) ||
       (cbAttestation != (pAttestation->HeaderSize +
                          pAttestation->cbPcrValues +
                          pAttestation->cbQuote +
                          pAttestation->cbSignature +
                          pAttestation->cbLog)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Unpack the attestation blob
    cursor = pAttestation->HeaderSize;
    pbPcrValues = &pbAttestation[cursor];
    cbPcrValues = pAttestation->cbPcrValues;
    cursor += pAttestation->cbPcrValues;
    if(pAttestation->cbQuote != 0)
    {
        pbQuote = &pbAttestation[cursor];
        cbQuote = pAttestation->cbQuote;
        cursor += pAttestation->cbQuote;
    }
    if(pAttestation->cbSignature != 0)
    {
        pbSignature = &pbAttestation[cursor];
        cbSignature = pAttestation->cbSignature;
        cursor += pAttestation->cbSignature;
    }
    pbLog = &pbAttestation[cursor];
    cbLog = pAttestation->cbLog;
    cursor += pAttestation->cbLog;

    // Remote attestation?
    if(hAik != NULL)
    {
        // Step 1: Calculate the digest of the quote
        if(FAILED(hr = TpmAttiShaHash(
                            BCRYPT_SHA1_ALGORITHM,
                            NULL,
                            0,
                            pbQuote,
                            cbQuote,
                            quoteDigest,
                            sizeof(quoteDigest),
                            &cbQuoteDigest)))
        {
            goto Cleanup;
        }

        // Step 2: Verify the signature with the public AIK
        if(FAILED(hr = HRESULT_FROM_NT(BCryptVerifySignature(
                                            hAik,
                                            &pPkcs,
                                            quoteDigest,
                                            sizeof(quoteDigest),
                                            pbSignature,
                                            cbSignature,
                                            BCRYPT_PAD_PKCS1))))
        {
            goto Cleanup;
        }

        // Step 3: Platform specific verification of nonce and pcrlist and receive the pcrMask in the quote
        if(pAttestation->Platform == TPM_VERSION_12)
        {
            if(FAILED(hr = ValidateQuoteContext12(
                                pbQuote,
                                cbQuote,
                                pbPcrValues,
                                cbPcrValues,
                                pbNonce,
                                cbNonce,
                                &pcrMask)))
            {
                goto Cleanup;
            }
        }
        else if(pAttestation->Platform == TPM_VERSION_20)
        {
            if(FAILED(hr = ValidateQuoteContext20(
                                pbQuote,
                                cbQuote,
                                pbPcrValues,
                                cbPcrValues,
                                pbNonce,
                                cbNonce,
                                &pcrMask)))
            {
                goto Cleanup;
            }
        }
        else
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
    }

    // Step 4: Calculate log PCRs
    if(FAILED(hr = TpmAttiComputeSoftPCRs(pbLog, cbLog, softwarePCR, &pcrMaskLog)))
    {
        goto Cleanup;
    }

    if(hAik == 0)
    {
        pcrMask = pcrMaskLog;
    }

    // Step 5: Comapre the PCRs from the quote with the PCRs from the log
    for(UINT32 n = 0; n < AVAILABLE_PLATFORM_PCRS; n++)
    {
        BYTE zeroInitializedPCR[SHA1_DIGEST_SIZE] = {0};
        BYTE ffInitializedPCR[SHA1_DIGEST_SIZE] = {0xff, 0xff, 0xff, 0xff, 0xff,
                                                   0xff, 0xff, 0xff, 0xff, 0xff,
                                                   0xff, 0xff, 0xff, 0xff, 0xff,
                                                   0xff, 0xff, 0xff, 0xff, 0xff};
        if((pcrMask & (0x00000001 << n)) == 0)
        {
            // Identify events in the log, not covered by the quote
            if((memcmp(&softwarePCR[SHA1_DIGEST_SIZE * n], zeroInitializedPCR, SHA1_DIGEST_SIZE) != 0) &&
               (memcmp(&softwarePCR[SHA1_DIGEST_SIZE * n], ffInitializedPCR, SHA1_DIGEST_SIZE) != 0))
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }
        }
        else
        {
            // Check log PCRs with quote PCRs
            if(memcmp(&pbPcrValues[SHA1_DIGEST_SIZE * n], &softwarePCR[SHA1_DIGEST_SIZE * n], SHA1_DIGEST_SIZE) != 0)
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }
        }
   }

    // Step 6: Optional - Local attestation
    if(hAik == 0)
    {
        BYTE currentPCR[AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE] = {0};
        UINT32 cbCurrentPCR = sizeof(currentPCR);
        UINT32 tpmVersion = 0;
        TBS_CONTEXT_PARAMS2 contextParams;
        contextParams.version = TBS_CONTEXT_VERSION_TWO;
        contextParams.asUINT32 = 0;
        contextParams.includeTpm12 = 1;
        contextParams.includeTpm20 = 1;

        // Get TPM version to select implementation
        if(FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
        {
            goto Cleanup;
        }

        // Open a TBS session to read the PCRs
        if(FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
        {
            goto Cleanup;
        }

        if(tpmVersion == TPM_VERSION_12)
        {
            // Get the PCRs
            if(FAILED(hr = GetPlatformPcrs12(
                                hPlatformTbsHandle,
                                currentPCR,
                                cbCurrentPCR,
                                &cbCurrentPCR)))
            {
                goto Cleanup;
            }
        }
        else if(tpmVersion == TPM_VERSION_20)
        {
            // Get the PCRs
            if(FAILED(hr = GetPlatformPcrs20(
                                hPlatformTbsHandle,
                                currentPCR,
                                cbCurrentPCR,
                                &cbCurrentPCR)))
            {
                goto Cleanup;
            }
        }
        else
        {
            hr = E_FAIL;
            goto Cleanup;
        }

        for(UINT32 n = 0; n < AVAILABLE_PLATFORM_PCRS; n++)
        {
            if((pcrMaskLog & (0x00000001 << n)) != 0)
            {
                // Check PCRs with platform PCRs
                if(memcmp(&pbPcrValues[SHA1_DIGEST_SIZE * n], &currentPCR[SHA1_DIGEST_SIZE * n], SHA1_DIGEST_SIZE) != 0)
                {
                    hr = E_INVALIDARG;
                    goto Cleanup;
                }
            }
       }
    }

    // Congratulations! Everything checks out and the log data may be considered trustworthy

Cleanup:
    // Close the TBS handle if we opened it in here
    if(hPlatformTbsHandle != NULL)
    {
        Tbsip_Context_Close(hPlatformTbsHandle);
        hPlatformTbsHandle = NULL;
    }
    return hr;
}

/// <summary>
/// Turn a log with a trust point into an attestation blob, so it can be validated as any other attestation blob
/// </summary>
/// <param name="pbLog">pointer to Event log with trust point</param>
/// <param name="cbLog">size of Event log with trust point</param>
/// <param name="szAikNameRequested">Optional AIK name selection, if multiple AIK are registered</param>
/// <param name="pszAikName">
/// Upon successful return, contains a pointer to the AIK name that signed the trust point.
/// This is a pointer into pbLog, cbLog and does not need to be explicitly freed.
/// </param>
/// <param name="pbAikPubDigest">pointer to receive AIK pub digest.</param>
/// <param name="pbOutput">Upon successful return, contains the attestation blob.</param>
/// <param name="cbOutput">input size of attestation blob buffer.</param>
/// <param name="pcbResult">output size of attestation blob buffer.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttCreateAttestationfromLog(
    _In_reads_(cbLog) PBYTE pbLog,
    UINT32 cbLog,
    _In_reads_z_(MAX_PATH) PWSTR szAikNameRequested,
    _Outptr_result_z_ PWSTR* pszAikName,
    _Out_writes_all_opt_(20) PBYTE pbAikPubDigest,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    )
{
    HRESULT hr = S_OK;
    PTCG_PCClientPCREventStruct pEntry = NULL;
    PWSTR szAikNameInternal = NULL;
    BOOLEAN tTrustpointFound = FALSE;
    BOOLEAN tTrustpointComplete = FALSE;
    PBYTE pbAikPubDig = NULL;
    UINT32 cbAikPubDig = 0;
    PBYTE pbQuote = NULL;
    UINT32 cbQuote = 0;
    PBYTE pbSig = NULL;
    UINT32 cbSig = 0;
    UINT32 cbFilteredLog = 0;
    UINT32 cbRequired = 0;
    PPCP_PLATFORM_ATTESTATION_BLOB pAttestation = (PPCP_PLATFORM_ATTESTATION_BLOB)pbOutput;
    UINT32 cursor = 0;
    const BYTE tpm12QuoteHdr[] = {0x00, 0x36, 0x51, 0x55, 0x54, 0x32};
    const BYTE tpm20QuoteHdr[] = {0xFF, 0x54, 0x43, 0x47, 0x80, 0x18};

    // Check the parameters
    if((pbLog == NULL) ||
       (cbLog == 0))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Parse the log
    for(pEntry = (PTCG_PCClientPCREventStruct)pbLog;
        ((PBYTE)pEntry - pbLog + sizeof(TCG_PCClientPCREventStruct) -
                                sizeof(BYTE)) < cbLog;
        pEntry = (PTCG_PCClientPCREventStruct) (((PBYTE)pEntry) +
                           sizeof(TCG_PCClientPCREventStruct) -
                           sizeof(BYTE) +
                           pEntry->eventDataSize))
    {
        ULONG cbEntry = sizeof(TCG_PCClientPCREventStruct) -
                        sizeof(BYTE) +
                        pEntry->eventDataSize;
        
        // Make sure that we have a proper entry
        if(((PBYTE)pEntry - pbLog + cbEntry) > cbLog)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        // Identify the entry to see if the TCG entry points to a trustpoint
        if((pEntry->pcrIndex != TPM12_PCR_TRUSTPOINT) ||
           (pEntry->eventType != SIPAEV_NO_ACTION) ||
           (pEntry->eventDataSize < (sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE))))
        {
            continue;
        }

        // Identify that we have a valid trustpoint event
        PTCG_PCClientTaggedEventStruct pTrustPoint = (PTCG_PCClientTaggedEventStruct)pEntry->event;
        if((pTrustPoint->EventID != SIPAEVENT_TRUSTPOINT_AGGREGATION) ||
           (pTrustPoint->EventDataSize < (sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE))))
        {
            continue;
        }

        // If there are more than one trustpoint in the aggregation, pick the one the caller has indicated
        PTCG_PCClientTaggedEventStruct pQuote = (PTCG_PCClientTaggedEventStruct)&pTrustPoint->EventData;
        UINT32 trustpointCount = 0;
        if(pQuote->EventID != SIPAEVENT_TRUSTPOINT_AGGREGATION)
        {
            tTrustpointFound = TRUE;
            trustpointCount = 1;
            pQuote =(PTCG_PCClientTaggedEventStruct)pEntry->event;
        }
        else
        {
            // Count the trustpoints
            pQuote = (PTCG_PCClientTaggedEventStruct)&pTrustPoint->EventData[0];
            PTCG_PCClientTaggedEventStruct pQuoteInList = NULL;
            for(UINT32 n = 0;
                n < pTrustPoint->EventDataSize;
                n += sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE) + pQuoteInList->EventDataSize)
            {
                pQuoteInList = (PTCG_PCClientTaggedEventStruct)&pTrustPoint->EventData[n];
                if((pQuoteInList->EventID != SIPAEVENT_TRUSTPOINT_AGGREGATION) ||
                   (pTrustPoint->EventDataSize < (n + (sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE)))))
                {
                    hr = E_INVALIDARG;
                    goto Cleanup;
                }
                tTrustpointFound = TRUE;
                trustpointCount++;
            }
        }

        // No trustpoints found
        if(!tTrustpointFound)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        // Extract the necessary information from the selected trustpoint
        for(UINT32 m = 0; m < trustpointCount; m++)
        {
            WCHAR szAikNameFound[MAX_PATH] = {0};
            szAikNameInternal = NULL;
            for(UINT32 n = 0; n < pQuote->EventDataSize; )
            {
                PTCG_PCClientTaggedEventStruct pAttribute = (PTCG_PCClientTaggedEventStruct)&pQuote->EventData[n];
                if(pAttribute->EventID == SIPAEVENT_AIKID)
                {
                    if(memcpy_s(szAikNameFound, sizeof(szAikNameFound) - sizeof(WCHAR), pAttribute->EventData, pAttribute->EventDataSize))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    szAikNameInternal = (PWSTR)pAttribute->EventData;
                }
                else if((pAttribute->EventID == SIPAEVENT_AIKPUBDIGEST) &&
                        (pAttribute->EventDataSize == SHA1_DIGEST_SIZE))
                {
                    pbAikPubDig = pAttribute->EventData;
                    cbAikPubDig = pAttribute->EventDataSize;
                }
                else if(pAttribute->EventID == SIPAEVENT_QUOTE)
                {
                    pbQuote = pAttribute->EventData;
                    cbQuote = pAttribute->EventDataSize;
                }
                else if(pAttribute->EventID == SIPAEVENT_QUOTESIGNATURE)
                {
                    pbSig = pAttribute->EventData;
                    cbSig = pAttribute->EventDataSize;
                }
                n += sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE) + pAttribute->EventDataSize;
            }

            if(szAikNameRequested != NULL)
            {
                if((szAikNameInternal == NULL) ||
                   (wcscmp(szAikNameFound, szAikNameRequested) != 0))
                {
                    // This is not the requested trustpoint
                    szAikNameInternal = NULL;
                    pbAikPubDig = NULL;
                    cbAikPubDig = 0;
                    pbQuote = NULL;
                    cbQuote = 0;
                    pbSig = NULL;
                    cbSig = 0;
                    pQuote = (PTCG_PCClientTaggedEventStruct)((PBYTE)pQuote +
                                                              sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE) +
                                                              pQuote->EventDataSize);
                    continue;
                }
            }

            if((szAikNameInternal != NULL) &&
               (pbQuote != NULL) &&
               (pbSig != NULL))
            {
                tTrustpointComplete = TRUE;
                break;
            }
        }
    }

    if(!tTrustpointComplete)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Is Quote recognized?
    if((memcmp(pbQuote, tpm12QuoteHdr, sizeof(tpm12QuoteHdr)) != 0) &&
       (memcmp(pbQuote, tpm20QuoteHdr, sizeof(tpm20QuoteHdr)) != 0))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Filter Log for relevant entries. The tpm driver uses the pcrMask = 0x0000F77f
    if(FAILED(hr = TpmAttiFilterLog(pbLog,
                                    cbLog,
                                    0x0000F77f, //pcrmask used by driver
                                    NULL,
                                    0,
                                    &cbFilteredLog)))
    {
        goto Cleanup;
    }

    cbRequired = sizeof(PCP_PLATFORM_ATTESTATION_BLOB) +
                 SHA1_DIGEST_SIZE * AVAILABLE_PLATFORM_PCRS +
                 cbQuote +
                 cbSig +
                 cbFilteredLog;

    if((pbOutput == NULL) || (cbOutput == 0))
    {
        *pcbResult = cbRequired;
        goto Cleanup;
    }
    if(cbOutput < cbRequired)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    pAttestation->Magic = PCP_PLATFORM_ATTESTATION_MAGIC;
    if(memcmp(pbQuote, tpm12QuoteHdr, sizeof(tpm12QuoteHdr)) == 0)
    {
        pAttestation->Platform = TPM_VERSION_12;
    }
    else if(memcmp(pbQuote, tpm20QuoteHdr, sizeof(tpm20QuoteHdr)) == 0)
    {
        pAttestation->Platform = TPM_VERSION_20;
    }
    pAttestation->HeaderSize = sizeof(PCP_PLATFORM_ATTESTATION_BLOB);
    pAttestation->cbPcrValues = AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE;
    pAttestation->cbQuote = cbQuote;
    pAttestation->cbSignature = cbSig;
    pAttestation->cbLog = cbFilteredLog;
    cursor = pAttestation->HeaderSize;

    // Skip over PCR list in the log for now. We will fill this in after we have filtered the log
    cursor += AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE;

    // Copy quote
    if(memcpy_s(&pbOutput[cursor], cbOutput - cursor, pbQuote, cbQuote))
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    cursor += cbQuote;

    // Copy signature
    if(memcpy_s(&pbOutput[cursor], cbOutput - cursor, pbSig, cbSig))
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    cursor += cbSig;

    // Filter log
    if(FAILED(hr = TpmAttiFilterLog(pbLog,
                                    cbLog,
                                    0x0000F77f, //pcrmask used by driver
                                    &pbOutput[cursor],
                                    cbFilteredLog,
                                    &cbFilteredLog)))
    {
        goto Cleanup;
    }

    // Generate PCR list from the filtered log
    if(FAILED(hr = TpmAttiComputeSoftPCRs(&pbOutput[cursor],
                                          cbFilteredLog,
                                          &pbOutput[pAttestation->HeaderSize],
                                          NULL)))
    {
        goto Cleanup;
    }
    cursor += cbFilteredLog;

    // Return finalized attestation blob size
    *pcbResult = cursor;

    // Return the AIK name, used for the Quote, if requested
    if(pszAikName != NULL)
    {
        *pszAikName = szAikNameInternal;
    }

    if(pbAikPubDigest != NULL)
    {
        memcpy(pbAikPubDigest, pbAikPubDig, min(SHA1_DIGEST_SIZE, cbAikPubDig));
    }

Cleanup:
    return hr;
}

/// <summary>
/// Parse an attestation blob and return specific properties from it
/// </summary>
/// <param name="pbAttestation">pointer to Event log with trust point.</param>
/// <param name="cbAttestation">size of Event log with trust point.</param>
/// <param name="pEventCount">Starting event count in the log.</param>
/// <param name="pEventIncrements">Number of event increemtns in the log.</param>
/// <param name="pEventCounterId">Event counter ID - only valid on 1.2.</param>
/// <param name="pBootCount">Power-up counter - only valid on 2.0.</param>
/// <param name="pdwPropertyFlags">Property flags for this attestation.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGetPlatformAttestationProperties(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    _Out_opt_ PUINT64 pEventCount,
    _Out_opt_ PUINT64 pEventIncrements,
    _Out_opt_ PUINT64 pEventCounterId,
    _Out_opt_ PUINT64 pBootCount,
    _Out_opt_ PUINT32 pdwPropertyFlags

    )
{
    HRESULT hr = S_OK;
    PPCP_PLATFORM_ATTESTATION_BLOB pAttestation = (PPCP_PLATFORM_ATTESTATION_BLOB)pbAttestation;
    PBYTE pbPlatformLog = NULL;
    UINT32 cbPlatformLog = 0;
    PTCG_PCClientPCREventStruct pEntry = NULL;
    UINT64 InitialEventCount = 0L;
    UINT64 FinalEventCount = 0L;
    UINT64 EventCounterId = 0;
    UINT64 BootCount = 0L;
    UINT32 dwPropertyFlags = PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;

    // Check parameters
    if((pbAttestation == NULL) ||
       (cbAttestation < sizeof(PCP_PLATFORM_ATTESTATION_BLOB)) ||
       (pAttestation->Magic != PCP_PLATFORM_ATTESTATION_MAGIC) ||
       (cbAttestation != (pAttestation->HeaderSize +
                          pAttestation->cbPcrValues +
                          pAttestation->cbQuote +
                          pAttestation->cbSignature +
                          pAttestation->cbLog)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    pbPlatformLog = &pbAttestation[pAttestation->HeaderSize +
                                   pAttestation->cbPcrValues +
                                   pAttestation->cbQuote +
                                   pAttestation->cbSignature];
    cbPlatformLog = pAttestation->cbLog;

    // Parse the log
    for(pEntry = (PTCG_PCClientPCREventStruct)pbPlatformLog;
        ((PBYTE)pEntry - pbPlatformLog + sizeof(TCG_PCClientPCREventStruct) -
                                sizeof(BYTE)) < cbPlatformLog;
        pEntry = (PTCG_PCClientPCREventStruct) (((PBYTE)pEntry) +
                           sizeof(TCG_PCClientPCREventStruct) -
                           sizeof(BYTE) +
                           pEntry->eventDataSize))
    {
        ULONG cbEntry = sizeof(TCG_PCClientPCREventStruct) -
                        sizeof(BYTE) +
                        pEntry->eventDataSize;

        // Make sure that we have a proper entry
        if(((PBYTE)pEntry - pbPlatformLog + cbEntry) > cbPlatformLog)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        // Identify the entry to see if the TCG entry contains a SIPA event
        if((pEntry->pcrIndex != TPM12_PCR_DETAILS) ||
           (pEntry->eventType != SIPAEV_EVENT_TAG) ||
           (pEntry->eventDataSize < (sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE))))
        {
            continue;
        }

        // Take that SIPA event apart
        UINT entrySize = 0;
        for(UINT32 n = 0; n < pEntry->eventDataSize; n += entrySize)
        {
            PTCG_PCClientTaggedEventStruct pSipaEvent = (PTCG_PCClientTaggedEventStruct)&pEntry->event[n];

            // Ensure that the buffer has enough space for the complete entry
            if((pEntry->eventDataSize < (n + sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE))) ||
               (pEntry->eventDataSize < (n +
                                         sizeof(TCG_PCClientTaggedEventStruct) -
                                         sizeof(BYTE) +
                                         pSipaEvent->EventDataSize)))
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }

            if((pSipaEvent->EventID & SIPAEVENTTYPE_AGGREGATION) != 0)
            {
                // We are looking at this file flat, so aggregations are meaningless
                entrySize = sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE);
                continue;
            }
            else
            {
                // regular entry
                entrySize = sizeof(TCG_PCClientTaggedEventStruct) - sizeof(BYTE) +
                            pSipaEvent->EventDataSize;
            }

            // Ignore informal entries
            if((pSipaEvent->EventID & SIPAEVENTTYPE_NONMEASURED) != 0)
            {
                continue;
            }

            switch(pSipaEvent->EventID)
            {
                case SIPAEVENT_BOOTCOUNTER:
                    if((pSipaEvent->EventDataSize != sizeof(UINT64)) ||
                       ((BootCount != 0L) &&
                        (*((PUINT64)pSipaEvent->EventData) != BootCount)))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    BootCount = *((PUINT64)pSipaEvent->EventData);
                    dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_CONTAINS_BOOT_COUNT;
                    break;
                case SIPAEVENT_EVENTCOUNTER:
                    if(pSipaEvent->EventDataSize != sizeof(UINT64))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(InitialEventCount == 0L)
                    {
                        InitialEventCount = *((PUINT64)pSipaEvent->EventData);
                        FinalEventCount = InitialEventCount;
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_CONTAINS_EVENT_COUNT;
                    }
                    else if(FinalEventCount == *((PUINT64)pSipaEvent->EventData) - 1)
                    {
                        FinalEventCount = *((PUINT64)pSipaEvent->EventData);
                    }
                    else
                    {
                        FinalEventCount = *((PUINT64)pSipaEvent->EventData);
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_EVENT_COUNT_NON_CONTIGUOUS;
                    }
                    break;
                case SIPAEVENT_COUNTERID:
                    if((pSipaEvent->EventDataSize != sizeof(UINT64)) ||
                       ((EventCounterId != 0L) &&
                        (*((PUINT64)pSipaEvent->EventData) != EventCounterId)))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    EventCounterId = *((PUINT64)pSipaEvent->EventData);
                    break;
                case SIPAEVENT_BOOTDEBUGGING:
                    if(pSipaEvent->EventDataSize != sizeof(BYTE))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(pSipaEvent->EventData[0] != 0)
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_BOOT_DEBUG_ON;
                    }
                    dwPropertyFlags &= ~PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;
                    break;
                case SIPAEVENT_BITLOCKER_UNLOCK:
                    if(pSipaEvent->EventDataSize != sizeof(UINT32))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(*((PUINT32)pSipaEvent->EventData) != 0)
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_BITLOCKER_UNLOCK;
                    }
                    dwPropertyFlags &= ~PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;
                    break;
                case SIPAEVENT_OSKERNELDEBUG:
                    if(pSipaEvent->EventDataSize != sizeof(BYTE))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(pSipaEvent->EventData[0] != 0)
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_OS_DEBUG_ON;
                    }
                    dwPropertyFlags &= ~PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;
                    break;
                case SIPAEVENT_CODEINTEGRITY:
                    if(pSipaEvent->EventDataSize != sizeof(BYTE))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(pSipaEvent->EventData[0] == 0)
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_CODEINTEGRITY_OFF;
                    }
                    dwPropertyFlags &= ~PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;
                    break;
                case SIPAEVENT_TESTSIGNING:
                    if(pSipaEvent->EventDataSize != sizeof(BYTE))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(pSipaEvent->EventData[0] != 0)
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_TESTSIGNING_ON;
                    }
                    dwPropertyFlags &= ~PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;
                    break;
                case SIPAEVENT_SAFEMODE:
                    if(pSipaEvent->EventDataSize != sizeof(BYTE))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(pSipaEvent->EventData[0] != 0)
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_OS_SAFEMODE;
                    }
                    dwPropertyFlags &= ~PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;
                    break;
                case SIPAEVENT_WINPE:
                    if(pSipaEvent->EventDataSize != sizeof(BYTE))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(pSipaEvent->EventData[0] != 0)
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_OS_WINPE;
                    }
                    dwPropertyFlags &= ~PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;
                    break;
                case SIPAEVENT_HYPERVISOR_LAUNCH_TYPE:
                    if(pSipaEvent->EventDataSize != sizeof(UINT64))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(*((PUINT64)pSipaEvent->EventData) != 0L)
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_OS_HV;
                    }
                    dwPropertyFlags &= ~PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;
                    break;
                case SIPAEVENT_TRANSFER_CONTROL:
                    if(pSipaEvent->EventDataSize != sizeof(UINT32))
                    {
                        hr = E_INVALIDARG;
                        goto Cleanup;
                    }
                    if(*((PUINT32)pSipaEvent->EventData) == 0x00000001) //SiBootAppOsLoader
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_WINLOAD;
                    }
                    else if(*((PUINT32)pSipaEvent->EventData) == 0x00000002) //SiBootAppResume
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_WINRESUME;
                    }
                    else
                    {
                        dwPropertyFlags |= PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_OTHER;
                    }
                    dwPropertyFlags &= ~PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED;
                    break;
            }
        }
    }

    if(pEventCount != NULL)
    {
        *pEventCount = InitialEventCount;
    }
    if(pEventIncrements != NULL)
    {
        *pEventIncrements = FinalEventCount - InitialEventCount;
    }
    if(pEventCounterId != NULL)
    {
        *pEventCounterId = EventCounterId;
    }
    if(pBootCount != NULL)
    {
        *pBootCount = BootCount;
    }
    if(pdwPropertyFlags != NULL)
    {
        *pdwPropertyFlags = dwPropertyFlags;
    }

Cleanup:
    return hr;
}

/// <summary>
/// Generate a key attestation. Both keys have to be on the TPM within the same provider handle.
/// </summary>
/// <param name="hAik">Key to sign the attestation - has to be fully authorized if necessary</param>
/// <param name="hKey">Key to be attested - has to be fully authorized if necessary</param>
/// <param name="pbNonce">pointer to optional nonce included in the signature</param>
/// <param name="cbNonce">size of optional nonce</param>
/// <param name="pbOutput">Upon successful return, contains the key certification blob.</param>
/// <param name="cbOutput">input size of certification blob buffer</param>
/// <param name="pcbResult">output size of certification blob buffer</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGenerateKeyAttestation(
    NCRYPT_KEY_HANDLE hAik,
    NCRYPT_KEY_HANDLE hKey,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    )
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_PROV_HANDLE hProvKey = NULL;
    UINT32 tpmVersion = 0;
    TBS_HCONTEXT hPlatformTbsHandle = 0;

    UINT32 hPlatformAikHandle = 0;
    BYTE tAikUsageAuthRequired = 0;
    BYTE aikUsageAuth[SHA1_DIGEST_SIZE] = {0};

    UINT32 hPlatformKeyHandle = 0;
    BYTE tUsageAuthRequired = 0;
    BYTE usageAuth[SHA1_DIGEST_SIZE] = {0};

    UINT32 cbRequired = 0;
    UINT32 cbCertify = 0;
    UINT32 cbSignature = 0;
    UINT32 cbKeyblob = 0;
    PPCP_KEY_ATTESTATION_BLOB pAttestationBlob = (PPCP_KEY_ATTESTATION_BLOB)pbOutput;
    UINT32 cursor = 0;

    // Check the parameters
    if((pcbResult == NULL) ||
       (hAik == NULL) ||
       (hKey == NULL))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    *pcbResult = 0;

    // Get TPM version to select implementation
    if(FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
    {
        goto Cleanup;
    }

    // Obtain the provider handle from the AIK so we can get to the TBS handle
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hAik,
                                        NCRYPT_PROVIDER_HANDLE_PROPERTY,
                                        (PUCHAR)&hProv,
                                        sizeof(hProv),
                                        (PULONG)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }

    // Obtain the provider handle from the key and check that both share the same provider handle
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hKey,
                                        NCRYPT_PROVIDER_HANDLE_PROPERTY,
                                        (PUCHAR)&hProvKey,
                                        sizeof(hProvKey),
                                        (PULONG)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }
    if(hProv != hProvKey)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Obtain the TBS handle that has been used to load the AIK and the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hProv,
                                        NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
                                        (PUCHAR)&hPlatformTbsHandle,
                                        sizeof(hPlatformTbsHandle),
                                        (PULONG)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }

    // Obtain the virtualized AIK TPM key handle that is used by the provider
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hAik,
                                        NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
                                        (PUCHAR)&hPlatformAikHandle,
                                        sizeof(hPlatformAikHandle),
                                        (PULONG)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }

    // Obtain the virtualized TPM key handle that is used by the provider
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hKey,
                                        NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
                                        (PUCHAR)&hPlatformKeyHandle,
                                        sizeof(hPlatformKeyHandle),
                                        (PULONG)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }

    // Obtain the size of the signature from this key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hAik,
                                        BCRYPT_SIGNATURE_LENGTH,
                                        (PUCHAR)&cbSignature,
                                        sizeof(cbSignature),
                                        (PULONG)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }

    // Does the AIK need authorization?
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hAik,
                                        NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY,
                                        (PUCHAR)&tAikUsageAuthRequired,
                                        sizeof(tAikUsageAuthRequired),
                                        (PULONG)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }
    if(tAikUsageAuthRequired != FALSE)
    {
        // Get the usageAuth from the provider
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hAik,
                                            NCRYPT_PCP_USAGEAUTH_PROPERTY,
                                            aikUsageAuth,
                                            sizeof(aikUsageAuth),
                                            (PULONG)&cbRequired,
                                            0))))
        {
            goto Cleanup;
        }
    }

    // Does the key need authorization?
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hKey,
                                        NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY,
                                        (PUCHAR)&tUsageAuthRequired,
                                        sizeof(tUsageAuthRequired),
                                        (PULONG)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }
    if(tUsageAuthRequired != FALSE)
    {
        // Get the usageAuth from the provider
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hKey,
                                            NCRYPT_PCP_USAGEAUTH_PROPERTY,
                                            usageAuth,
                                            sizeof(usageAuth),
                                            (PULONG)&cbRequired,
                                            0))))
        {
            goto Cleanup;
        }
    }

    // Get the size of the key blob
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                        hKey,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        NULL,
                                        NULL,
                                        0,
                                        (PULONG)&cbKeyblob,
                                        0))))
    {
        goto Cleanup;
    }

    if(tpmVersion == TPM_VERSION_12)
    {
        const BYTE nullBuffer[SHA1_DIGEST_SIZE] = {0};

        if(FAILED(hr = CertifyKey12(
                            hPlatformTbsHandle,
                            hPlatformAikHandle,
                            tAikUsageAuthRequired ? aikUsageAuth : NULL,
                            tAikUsageAuthRequired ? sizeof(aikUsageAuth) : 0,
                            hPlatformKeyHandle,
                            tUsageAuthRequired ? usageAuth : NULL,
                            tUsageAuthRequired ? sizeof(usageAuth) : 0,
                            (pbNonce) ? pbNonce : (PBYTE)nullBuffer,
                            (pbNonce) ? cbNonce : sizeof(nullBuffer),
                            NULL,
                            0,
                            &cbCertify)))
        {
            goto Cleanup;
        }
    }
    else if(tpmVersion == TPM_VERSION_20)
    {
        if(FAILED(hr = CertifyKey20(
                            hPlatformTbsHandle,
                            hPlatformAikHandle,
                            (tAikUsageAuthRequired) ? aikUsageAuth : NULL,
                            (tAikUsageAuthRequired) ? sizeof(aikUsageAuth) : 0,
                            hPlatformKeyHandle,
                            (tUsageAuthRequired) ? usageAuth : NULL,
                            (tUsageAuthRequired) ? sizeof(usageAuth) : 0,
                            pbNonce,
                            cbNonce,
                            NULL,
                            0,
                            &cbCertify)))
        {
            goto Cleanup;
        }
    }
    else
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Calculate output buffer
    cbRequired = sizeof(PCP_KEY_ATTESTATION_BLOB) +
                 cbCertify - cbSignature +
                 cbSignature +
                 cbKeyblob;
    if((pbOutput == NULL) || (cbOutput == 0))
    {
        *pcbResult = cbRequired;
        goto Cleanup;
    }
    if(cbOutput < cbRequired)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    // Create the output structure
    pAttestationBlob->Magic = PCP_KEY_ATTESTATION_MAGIC;
    pAttestationBlob->Platform = tpmVersion;
    pAttestationBlob->HeaderSize = sizeof(PCP_KEY_ATTESTATION_BLOB);
    pAttestationBlob->cbKeyAttest = cbCertify - cbSignature;
    pAttestationBlob->cbSignature = cbSignature;
    pAttestationBlob->cbKeyBlob = cbKeyblob;
    cursor = pAttestationBlob->HeaderSize;

    // Perform key attestation and obtain the certification
    if(tpmVersion == TPM_VERSION_12)
    {
        const BYTE nullBuffer[SHA1_DIGEST_SIZE] = {0};

        if(FAILED(hr = CertifyKey12(
                            hPlatformTbsHandle,
                            hPlatformAikHandle,
                            tAikUsageAuthRequired ? aikUsageAuth : NULL,
                            tAikUsageAuthRequired ? sizeof(aikUsageAuth) : 0,
                            hPlatformKeyHandle,
                            tUsageAuthRequired ? usageAuth : NULL,
                            tUsageAuthRequired ? sizeof(usageAuth) : 0,
                            (pbNonce) ? pbNonce : (PBYTE)nullBuffer,
                            (pbNonce) ? cbNonce : sizeof(nullBuffer),
                            &pbOutput[cursor],
                            pAttestationBlob->cbKeyAttest + pAttestationBlob->cbSignature,
                            &cbRequired)))
        {
            goto Cleanup;
        }
        cursor += cbRequired;
    }
    else if(tpmVersion == TPM_VERSION_20)
    {
        if(FAILED(hr = CertifyKey20(
                            hPlatformTbsHandle,
                            hPlatformAikHandle,
                            (tAikUsageAuthRequired) ? aikUsageAuth : NULL,
                            (tAikUsageAuthRequired) ? sizeof(aikUsageAuth) : 0,
                            hPlatformKeyHandle,
                            (tUsageAuthRequired) ? usageAuth : NULL,
                            (tUsageAuthRequired) ? sizeof(usageAuth) : 0,
                            pbNonce,
                            cbNonce,
                            &pbOutput[cursor],
                            pAttestationBlob->cbKeyAttest + pAttestationBlob->cbSignature,
                            &cbRequired)))
        {
            goto Cleanup;
        }
        cursor += cbRequired;
    }
    else
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Make OACR happy
    if((cursor + pAttestationBlob->cbKeyBlob) > cbOutput)
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Get the key blob
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                        hKey,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        NULL,
                                        &pbOutput[cursor],
                                        pAttestationBlob->cbKeyBlob,
                                        (PDWORD)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }
    cursor += cbRequired;

    // Return the final size
    *pcbResult = cursor;

Cleanup:
    return hr;
}

/// <summary>
/// Get a key attestation that was created by the provider.
/// </summary>
/// <param name="hKey">Key to be attested - has to be fully authorized if necessary</param>
/// <param name="szAikNameRequested">Optional AIK name selection, if multiple AIK are registered</param>
/// <param name="pszAikName">
/// Upon successful return, contains a pointer to the AIK name that signed the trust point.
/// This is a pointer into pbLog, cbLog and does not need to be explicitly freed.
/// </param>
/// <param name="pbAikPubDigest">pointer to receive AIK pub digest.</param>
/// <param name="pbOutput">Upon successful return, contains the key certification blob.</param>
/// <param name="cbOutput">input size of certification blob buffer</param>
/// <param name="pcbResult">output size of certification blob buffer</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttCreateAttestationfromKey(
    NCRYPT_KEY_HANDLE hKey,
    _In_reads_z_(MAX_PATH) PWSTR szAikNameRequested,
    _Out_writes_z_(MAX_PATH) PWSTR pszAikName,
    _Out_writes_all_opt_(20) PBYTE pbAikPubDigest,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    )
{
    HRESULT hr = S_OK;
    UINT32 cbRequired = 0;
    UINT32 attesttationTag = 0;
    PBYTE pbCertify = NULL;
    UINT32 cbCertify = 0;
    PBYTE pbSignature = NULL;
    UINT32 cbSignature = 0;
    UINT32 cbKeyblob = 0;
    PPCP_KEY_ATTESTATION_BLOB pAttestationBlob = (PPCP_KEY_ATTESTATION_BLOB)pbOutput;
    PBYTE pbAttestationData = NULL;
    UINT32 cbAttestationData = 0;
    LPWSTR szAikNameInternal = NULL;
    BOOLEAN tCertifyFound = FALSE;
    PBYTE pbAikPubDigestInternal = NULL;
    UINT32 cursor = 0;

    // Check the parameters
    if((pcbResult == NULL) ||
       (pszAikName == NULL) ||
       (hKey == NULL))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    *pcbResult = 0;
    pszAikName[0] = 0x0000;

    // Obtain the attestation Data from the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hKey,
                                        NCRYPT_PCP_KEYATTESTATION_PROPERTY,
                                        NULL,
                                        0,
                                        (PULONG)&cbAttestationData,
                                        0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestationData, cbAttestationData)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hKey,
                                        NCRYPT_PCP_KEYATTESTATION_PROPERTY,
                                        pbAttestationData,
                                        cbAttestationData,
                                        (PULONG)&cbAttestationData,
                                        0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                        hKey,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        NULL,
                                        NULL,
                                        0,
                                        (PULONG)&cbKeyblob,
                                        0))))
    {
        goto Cleanup;
    }

    // Ensure data package is valid
    if((cbAttestationData < sizeof(UINT32)) ||
       ((*((PUINT32)pbAttestationData) != 'AK1T') &&
        (*((PUINT32)pbAttestationData) != 'AK2T')))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    attesttationTag = *((PUINT32)pbAttestationData);
    cursor += sizeof(UINT32);

    while(cursor < cbAttestationData)
    {
        UINT16 cbAikName = 0;
        UINT16 cbAikPubDigestInternal = 0;

        // Skip the attestation package size
        if(cbAttestationData < cursor + sizeof(UINT32))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        cursor += sizeof(UINT32);

        // Retrieve the AIKName size
        if(cbAttestationData < cursor + sizeof(UINT16))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        cbAikName = *((PUINT16)&pbAttestationData[cursor]);
        cursor += sizeof(UINT16);
        if((cbAikName < sizeof(WCHAR)) ||
           (cbAttestationData < cursor + cbAikName))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        szAikNameInternal = (LPWSTR)&pbAttestationData[cursor];
        if(*((PWCHAR)&pbAttestationData[cursor + cbAikName - sizeof(WCHAR)]) != 0x0000)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        cursor += cbAikName;

        // Retrieve the AIKPubDigest
        if(cbAttestationData < cursor + sizeof(UINT16))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        cbAikPubDigestInternal = *((PUINT16)&pbAttestationData[cursor]);
        cursor += sizeof(UINT16);
        if((cbAikPubDigestInternal != SHA1_DIGEST_SIZE) ||
           (cbAttestationData < cursor + cbAikPubDigestInternal))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        pbAikPubDigestInternal = &pbAttestationData[cursor];
        cursor += cbAikPubDigestInternal;

        // Retieve the Attestation structure
        if(cbAttestationData < cursor + sizeof(UINT16))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        cbCertify = *((PUINT16)&pbAttestationData[cursor]);
        cursor += sizeof(UINT16);
        if(cbAttestationData < cursor + cbCertify)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        pbCertify = &pbAttestationData[cursor];
        cursor += cbCertify;

        // Retieve the signature structure
        if(cbAttestationData < cursor + sizeof(UINT16))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        cbSignature = *((PUINT16)&pbAttestationData[cursor]);
        cursor += sizeof(UINT16);
        if(cbAttestationData < cursor + cbSignature)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        pbSignature = &pbAttestationData[cursor];
        cursor += cbSignature;

        // See if this is the attestation blob that was requested
        if((szAikNameRequested == NULL) ||
           (!wcscmp(szAikNameInternal, szAikNameRequested)))
        {
            tCertifyFound = TRUE;
            if(FAILED(hr = StringCchCopyW(pszAikName, MAX_PATH, szAikNameInternal)))
            {
                goto Cleanup;
            }
            if(pbAikPubDigest != NULL)
            {
                memcpy(pbAikPubDigest, pbAikPubDigestInternal, SHA1_DIGEST_SIZE);
            }
            break;
        }
    }

    // We did not find the specified name
    if(!tCertifyFound)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Calculate output buffer
    cbRequired = sizeof(PCP_KEY_ATTESTATION_BLOB) +
                 cbCertify +
                 cbSignature +
                 cbKeyblob;
    if((pbOutput == NULL) || (cbOutput == 0))
    {
        *pcbResult = cbRequired;
        goto Cleanup;
    }
    if(cbOutput < cbRequired)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    // Create the output structure
    pAttestationBlob->Magic = PCP_KEY_ATTESTATION_MAGIC;
    if(attesttationTag == 'AK1T')
    {
        pAttestationBlob->Platform = TPM_VERSION_12;
    }
    else if(attesttationTag == 'AK2T')
    {
        pAttestationBlob->Platform = TPM_VERSION_20;
    }
    else
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    pAttestationBlob->HeaderSize = sizeof(PCP_KEY_ATTESTATION_BLOB);
    pAttestationBlob->cbKeyAttest = cbCertify;
    pAttestationBlob->cbSignature = cbSignature;
    pAttestationBlob->cbKeyBlob = cbKeyblob;
    cursor = pAttestationBlob->HeaderSize;
    memcpy(&pbOutput[cursor], pbCertify, cbCertify);
    cursor += cbCertify;
    memcpy(&pbOutput[cursor], pbSignature, cbSignature);
    cursor += cbSignature;

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                        hKey,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        NULL,
                                        &pbOutput[cursor],
                                        cbRequired - cursor,
                                        (PULONG)&cbKeyblob,
                                        0))))
    {
        goto Cleanup;
    }
    cursor += cbKeyblob;
    *pcbResult = cursor;
Cleanup:
    ZeroAndFree((PVOID*)&pbAttestationData, cbAttestationData);
    return hr;
}

/// <summary>
/// Integrity validation of a key certification. Usually done on a server.
/// </summary>
/// <param name="hAik">Public key to validate the attestation.</param>
/// <param name="pbNonce">Optional nonce validated with certification if provided.</param>
/// <param name="cbNonce">size of optional nonce.</param>
/// <param name="pbAttestation">Key certification blob.</param>
/// <param name="cbAttestation">size of key certification blob.</param>
/// <param name="pcrMask">Expected pceMask of key. Validated with pcrMask in the key.</param>
/// <param name="pcrTable">
/// All 24 PCRs that the pcr digest is validated with.
/// This is used to check the PCR policy a key is bound to.
/// </param>
/// <param name="cbPcrTable">size of PCR table</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttValidateKeyAttestation(
    BCRYPT_KEY_HANDLE hAik,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    UINT32 pcrMask,
    _In_reads_opt_(cbPcrTable) PBYTE pcrTable,
    UINT32 cbPcrTable
    )
{
    HRESULT hr = S_OK;
    PPCP_KEY_ATTESTATION_BLOB pAttestation = (PPCP_KEY_ATTESTATION_BLOB)pbAttestation;
    UINT32 cursor = 0;
    PBYTE pbKeyAttest = NULL;
    UINT32 cbKeyAttest = 0;
    PBYTE pbSignature = NULL;
    UINT32 cbSignature = 0;
    PBYTE pbKeyBlob = NULL;
    UINT32 cbKeyBlob = 0;
    BYTE attestDigest[SHA1_DIGEST_SIZE] = {0};
    UINT32 cbAttestDigest = 0;
    BCRYPT_PKCS1_PADDING_INFO pPkcs = {BCRYPT_SHA1_ALGORITHM};

    // Check the parameters
    if((hAik == NULL) ||
       (pbAttestation == NULL) ||
       (cbAttestation < sizeof(PCP_KEY_ATTESTATION_BLOB)) ||
       (pAttestation->Magic != PCP_KEY_ATTESTATION_MAGIC) ||
       (cbAttestation != (pAttestation->HeaderSize +
                          pAttestation->cbKeyAttest +
                          pAttestation->cbSignature +
                          pAttestation->cbKeyBlob)) ||
       ((pcrTable != NULL) && (cbPcrTable != AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Unpack the attestation blob
    cursor = pAttestation->HeaderSize;
    pbKeyAttest = &pbAttestation[cursor];
    cbKeyAttest = pAttestation->cbKeyAttest;
    cursor += pAttestation->cbKeyAttest;
    pbSignature = &pbAttestation[cursor];
    cbSignature = pAttestation->cbSignature;
    cursor += pAttestation->cbSignature;
    pbKeyBlob = &pbAttestation[cursor];
    cbKeyBlob = pAttestation->cbKeyBlob;
    cursor += pAttestation->cbKeyBlob;

    // Step 1: Calculate the digest of the certify
    if(FAILED(hr = TpmAttiShaHash(
                        BCRYPT_SHA1_ALGORITHM,
                        NULL,
                        0,
                        pbKeyAttest,
                        cbKeyAttest,
                        attestDigest,
                        sizeof(attestDigest),
                        &cbAttestDigest)))
    {
        goto Cleanup;
    }

    // Step 2: Verify the signature with the public AIK
    if(FAILED(hr = HRESULT_FROM_NT(BCryptVerifySignature(
                                        hAik,
                                        &pPkcs,
                                        attestDigest,
                                        sizeof(attestDigest),
                                        pbSignature,
                                        cbSignature,
                                        BCRYPT_PAD_PKCS1))))
    {
        goto Cleanup;
    }

    // Step 3: Platform specific verification of nonce, public key name and PCR policy
    if(pAttestation->Platform == TPM_VERSION_12)
    {
        if(FAILED(hr = ValidateKeyAttest12(
                            pbKeyAttest,
                            cbKeyAttest,
                            pbNonce,
                            cbNonce,
                            pbKeyBlob,
                            cbKeyBlob,
                            pcrMask,
                            pcrTable)))
        {
            goto Cleanup;
        }
    }
    else if(pAttestation->Platform == TPM_VERSION_20)
    {
        if(FAILED(hr = ValidateKeyAttest20(
                            pbKeyAttest,
                            cbKeyAttest,
                            pbNonce,
                            cbNonce,
                            pbKeyBlob,
                            cbKeyBlob,
                            pcrMask,
                            pcrTable)))
        {
            goto Cleanup;
        }
    }
    else
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Congratulations! Everything checks out and the key may be considered trustworthy

Cleanup:
    return hr;
}

/// <summary>
/// Retrieve a public key handle and key property flags form a key attestation. This funciton is usually called on a server.
/// </summary>
/// <param name="pbAttestation">Validated attestation blob.</param>
/// <param name="cbAttestation">size of validated attestation blob.</param>
/// <param name="pPropertyFlags">Upon successful return, contains the key property flags.</param>
/// <param name="hAlg">Provider that should be used to open the key handle in.</param>
/// <param name="phKey">Upon successful return, contains the public key handle</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGetKeyAttestationProperties(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    _Out_opt_ PUINT32 pPropertyFlags,
    BCRYPT_ALG_HANDLE hAlg,
    _Out_opt_ BCRYPT_KEY_HANDLE* phKey
    )
{
    HRESULT hr = S_OK;
    PPCP_KEY_ATTESTATION_BLOB pAttestation = (PPCP_KEY_ATTESTATION_BLOB)pbAttestation;
    UINT32 cursor = 0;
    PBYTE pbKeyBlob = NULL;
    UINT32 cbKeyBlob = 0;

    // Check the parameters
    if(((phKey != NULL) && (hAlg == NULL)) ||
       (pbAttestation == NULL) ||
       (cbAttestation < sizeof(PCP_KEY_ATTESTATION_BLOB)) ||
       (pAttestation->Magic != PCP_KEY_ATTESTATION_MAGIC) ||
       (cbAttestation != (pAttestation->HeaderSize +
                          pAttestation->cbKeyAttest +
                          pAttestation->cbSignature +
                          pAttestation->cbKeyBlob)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Unpack the attestation blob
    cursor = pAttestation->HeaderSize +
             pAttestation->cbKeyAttest +
             pAttestation->cbSignature;
    pbKeyBlob = &pbAttestation[cursor];
    cbKeyBlob = pAttestation->cbKeyBlob;
    cursor += pAttestation->cbKeyBlob;

    if(phKey != NULL)
    {
        if(pAttestation->Platform == TPM_VERSION_12)
        {
            PPCP_KEY_BLOB p12Key = (PPCP_KEY_BLOB)pbKeyBlob;
            if((p12Key == NULL) ||
               (cbKeyBlob < sizeof(PCP_KEY_BLOB)) ||
               (p12Key->magic != BCRYPT_PCP_KEY_MAGIC) ||
               (p12Key->cbHeader < sizeof(PCP_KEY_BLOB)) ||
               (p12Key->pcpType != PCPTYPE_TPM12) ||
               (cbKeyBlob < p12Key->cbHeader +
                            p12Key->cbTpmKey))
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }
            if(FAILED(hr = GetKeyHandleFromKeyBlob12(
                                &pbKeyBlob[p12Key->cbHeader],
                                p12Key->cbTpmKey,
                                hAlg,
                                phKey,
                                NULL)))
            {
                goto Cleanup;
            }
        }
        else if(pAttestation->Platform == TPM_VERSION_20)
        {
            PPCP_KEY_BLOB_WIN8 pW8Key = (PPCP_KEY_BLOB_WIN8)pbKeyBlob;
            if((pW8Key == NULL) ||
               (cbKeyBlob < sizeof(PCP_KEY_BLOB_WIN8)) ||
               (pW8Key->magic != BCRYPT_PCP_KEY_MAGIC) ||
               (pW8Key->cbHeader < sizeof(PCP_KEY_BLOB_WIN8)) ||
               (pW8Key->pcpType != PCPTYPE_TPM20) ||
               (cbKeyBlob < pW8Key->cbHeader +
                            pW8Key->cbPublic +
                            pW8Key->cbPrivate +
                            pW8Key->cbMigrationPublic +
                            pW8Key->cbMigrationPrivate +
                            pW8Key->cbPolicyDigestList +
                            pW8Key->cbPCRBinding +
                            pW8Key->cbPCRDigest +
                            pW8Key->cbEncryptedSecret +
                            pW8Key->cbTpm12HostageBlob))
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }
            if(FAILED(hr = GetKeyHandleFromPubKeyBlob20(
                                &pbKeyBlob[pW8Key->cbHeader + sizeof(UINT16)],
                                pW8Key->cbPublic - sizeof(UINT16),
                                hAlg,
                                phKey,
                                NULL,
                                NULL)))
            {
                goto Cleanup;
            }
        }
        else
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
    }

    if(pPropertyFlags != NULL)
    {
        if(pAttestation->Platform == TPM_VERSION_12)
        {
            if(FAILED(hr = GetKeyProperties12(
                                pbKeyBlob,
                                cbKeyBlob,
                                pPropertyFlags)))
            {
                goto Cleanup;
            }
        }
        else if(pAttestation->Platform == TPM_VERSION_20)
        {
            if(FAILED(hr = GetKeyProperties20(
                                pbKeyBlob,
                                cbKeyBlob,
                                pPropertyFlags)))
            {
                goto Cleanup;
            }
        }
        else
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
    }

Cleanup:
    return hr;
}

/// <summary>
/// Wrap a platform key with a given set of policies for a particular target machine. This function is usually called on a server.
/// </summary>
/// <param name="hInKey">Handle to an exportable key pair.</param>
/// <param name="hStorageKey">Public storage key that will be the new parent of inKey. Has to be a storage key.</param>
/// <param name="tpmVersion">Selector if a 1.2 or 2.0 key blob is to be created.</param>
/// <param name="keyUsage">Key usage restriction.</param>
/// <param name="pbPIN">Optional user PIN value that the key should be bound to.</param>
/// <param name="cbPIN">size of optional PIN value</param>
/// <param name="pcrMask">Optional PCRMask the key will be bound to</param>
/// <param name="pcrTable">PCR table of 24 digests that will be used to calculate the PCR digest with the pcrMask</param>
/// <param name="cbPcrTable">size of PCR table</param>
/// <param name="pbOutput">Upon successful return, contains the wrapped key blob.</param>
/// <param name="cbOutput">input size of key blob</param>
/// <param name="pcbResult">output size of key blob</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttWrapPlatformKey(
    NCRYPT_KEY_HANDLE hInKey,
    BCRYPT_KEY_HANDLE hStorageKey,
    UINT32 tpmVersion,
    UINT32 keyUsage,
    _In_reads_opt_(cbPIN) PBYTE pbPIN,
    UINT32 cbPIN,
    UINT32 pcrMask,
    _In_reads_opt_(cbPcrTable) PBYTE pcrTable,
    UINT32 cbPcrTable,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
    )
{
    HRESULT hr = S_OK;
    UINT32 cbRequired = 0;
    PBYTE pbKeyPair = NULL;
    UINT32 cbKeyPair = 0;
    UINT32 exportPolicy = 0;
    BOOLEAN tUsageAuthSet = FALSE;
    BYTE usageAuth[SHA1_DIGEST_SIZE] = {0};

    // Check the parameters
    if((hInKey == NULL) ||
       (hStorageKey == NULL) ||
       ((pcrTable != NULL) && (cbPcrTable != AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE)) ||
       ((tpmVersion != TPM_VERSION_20) && (tpmVersion != TPM_VERSION_12)) ||
       ((keyUsage & 0x0000ffff & ~(NCRYPT_PCP_GENERIC_KEY | NCRYPT_PCP_STORAGE_KEY)) != 0))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Is the InKey exportable?
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hInKey,
                                        NCRYPT_EXPORT_POLICY_PROPERTY ,
                                        (PUCHAR)&exportPolicy,
                                        sizeof(exportPolicy),
                                        (PULONG)&cbRequired,
                                        0))))
    {
        goto Cleanup;
    }
    if(((exportPolicy & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG) == 0) ||
       ((exportPolicy & NCRYPT_ALLOW_EXPORT_FLAG) == 0))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Export the key pair
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                        hInKey,
                                        NULL,
                                        BCRYPT_RSAPRIVATE_BLOB,
                                        NULL,
                                        NULL,
                                        0,
                                        (PDWORD)&cbKeyPair,
                                        0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbKeyPair, cbKeyPair)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                        hInKey,
                                        NULL,
                                        BCRYPT_RSAPRIVATE_BLOB,
                                        NULL,
                                        pbKeyPair,
                                        cbKeyPair,
                                        (PDWORD)&cbKeyPair,
                                        0))))
    {
        goto Cleanup;
    }

    // Create the usageAuth from the PIN
    if((pbPIN != NULL) && (cbPIN != 0))
    {
        if(FAILED(hr = TpmAttiShaHash(
                            BCRYPT_SHA1_ALGORITHM,
                            NULL,
                            0,
                            pbPIN,
                            cbPIN,
                            usageAuth,
                            sizeof(usageAuth),
                            &cbRequired)))
        {
            goto Cleanup;
        }
        tUsageAuthSet = TRUE;
    }

    if(tpmVersion == TPM_VERSION_12)
    {
        if(FAILED(hr = WrapPlatformKey12(pbKeyPair,
                                         cbKeyPair,
                                         hStorageKey,
                                         keyUsage,
                                         tUsageAuthSet ? usageAuth : NULL,
                                         tUsageAuthSet ? sizeof(usageAuth) : 0,
                                         pcrMask,
                                         pcrTable,
                                         pbOutput,
                                         cbOutput,
                                         pcbResult)))
        {
            goto Cleanup;
        }
    }
    else if(tpmVersion == TPM_VERSION_20)
    {
        if(FAILED(hr = WrapPlatformKey20(pbKeyPair,
                                         cbKeyPair,
                                         hStorageKey,
                                         keyUsage,
                                         tUsageAuthSet ? usageAuth : NULL,
                                         tUsageAuthSet ? sizeof(usageAuth) : 0,
                                         pcrMask,
                                         pcrTable,
                                         pbOutput,
                                         cbOutput,
                                         pcbResult)))
        {
            goto Cleanup;
        }
    }

Cleanup:
    ZeroAndFree((PVOID*)&pbKeyPair, cbKeyPair);
    return hr;
}

/// <summary>
/// Get the TPM_NV_LIST
/// </summary>
/// <param name="hAik">AIK key handle, fully authorized if required.</param>
/// <param name="pcrMask">Filter for events.</param>
/// <param name="pbNonce">pointer to Nonce provided to be included in signature.</param>
/// <param name="cbNonce">size of Nonce provided to be included in signature.</param>
/// <param name="pbOutput">Upon successful return, contains the attestation blob.</param>
/// <param name="cbOutput">input size of attestation blob buffer.</param>
/// <param name="pcbResult">output size of attestation blob.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmNVInfo(
	UINT32 nvIndex,
	_Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
	UINT32 cbOutput,
	_Out_ PUINT32 pcbResult
	)
{
	HRESULT hr = 0;
	TBS_CONTEXT_PARAMS2 contextParams;
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	UINT32 tpmVersion;
	UINT32 list_only = 1;
	UINT32 indexFound = 0;
	
	if (nvIndex > 0)
		list_only = 0;

	// Get TPM version to select implementation
	if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
	{
		goto Cleanup;
	}

	//get the tbs handle
	contextParams.version = TBS_CONTEXT_VERSION_TWO;
	contextParams.asUINT32 = 0;
	contextParams.includeTpm12 = 1;
	contextParams.includeTpm20 = 1;
	if (FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
	{
		goto Cleanup;
	}

	//wprintf(L" Platform TBS Handle opened successfully\n");

	//dispatch based on TPM version
	if (tpmVersion == TPM_VERSION_12)
	{
		// 0x0000000D TPM_CAP_NV_LIST 
		if (FAILED(hr = GetCapability12(hPlatformTbsHandle, 0x0000000D, NULL, 0, pbOutput, cbOutput, pcbResult)))
		{
			goto Cleanup;
		}
		//wprintf(L" GetCapability12 returns successfully\n");
		//wprintf(L" Return size is: %d\n", *pcbResult);

		UINT32 cursor = 0;
		for (int i = 0; i < *pcbResult / sizeof(UINT32); i++) {
			UINT32 nvi;
			ReadBigEndian(pbOutput, *pcbResult, &cursor, &nvi);
			if (nvIndex == nvi || list_only==1) {
				indexFound = 1;
				wprintf(L"NVRAM index defined	: 0x%08x (%d)\n", nvi, nvi);
			}
		}
		if (nvIndex>0 && indexFound == 0) {
			wprintf(L"index 0x%08x not defined\n", nvIndex);
		}
		// 0x00000011 TPM_CAP_NV_INDEX - to get the TPM_NV_DATA_PUBLIC info of the index

	}
	else if (tpmVersion == TPM_VERSION_20)
	{
		//Not implemented yet
	}
	else
	{
		hr = E_FAIL;
		goto Cleanup;
	}

Cleanup:
	// Close the TBS handle if we opened it in here
	if (hPlatformTbsHandle != NULL)
	{
		Tbsip_Context_Close(hPlatformTbsHandle);
		hPlatformTbsHandle = NULL;
	}
	return hr;
}

DllExport HRESULT TpmNVDefineSpace(
	UINT32 nvIndex,
	UINT32 indexSize,
	PBYTE nvAuth, 
	PCWSTR permissions
	) 
{
	HRESULT hr = 0;
	TBS_CONTEXT_PARAMS2 contextParams;
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	UINT32 tpmVersion;
	BYTE pbOwnerAuth[256] = { 0 };
	UINT32 cbOwnerAuth = 256;

	// Get TPM version to select implementation
	if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
	{
		goto Cleanup;
	}
	//get the tbs handle
	contextParams.version = TBS_CONTEXT_VERSION_TWO;
	contextParams.asUINT32 = 0;
	contextParams.includeTpm12 = 1;
	contextParams.includeTpm20 = 1;
	if (FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
	{
		goto Cleanup;
	}
	// get ownerAuth
	if (FAILED(hr = Tbsi_Get_OwnerAuth(hPlatformTbsHandle, TBS_OWNERAUTH_TYPE_FULL, pbOwnerAuth, &cbOwnerAuth))) {
		goto Cleanup;
	}
	/* Debug
	wprintf(L" ownerauth read by calling Tbsi_Get_OwnerAuth: ", cbOwnerAuth);
	for (UINT32 i = 0; i < cbOwnerAuth; i++) {
		wprintf(L"%02x", pbOwnerAuth[i]);
	}
	wprintf(L"\n");
	*/
	//dispatch based on TPM version
	
	#define TPM_NV_PER_READ_STCLEAR                 (((UINT32)1)<<31)
	#define TPM_NV_PER_AUTHREAD						(((UINT32)1)<<18)
	#define TPM_NV_PER_OWNERREAD                    (((UINT32)1)<<17)
	#define TPM_NV_PER_WRITEALL						(((UINT32)1)<<12)
	#define TPM_NV_PER_AUTHWRITE					(((UINT32)1)<<2)
	#define	TPM_NV_PER_OWNERWRITE					(((UINT32)1)<<1)

	if (tpmVersion == TPM_VERSION_12)
	{
		if (FAILED(hr = NvDefineSpace12(hPlatformTbsHandle, nvIndex, indexSize, pbOwnerAuth, cbOwnerAuth, nvAuth, 20, TPM_NV_PER_AUTHWRITE)))
		{
			goto Cleanup;
		}
		//wprintf(L"TPM nvdefine returned successfully!\n");
	}
	else if (tpmVersion == TPM_VERSION_20)
	{
		//Not implemented yet
	}
	else
	{
		hr = E_FAIL;
		goto Cleanup;
	}

Cleanup:
	// Close the TBS handle if we opened it in here
	if (hPlatformTbsHandle != NULL)
	{
		Tbsip_Context_Close(hPlatformTbsHandle);
		hPlatformTbsHandle = NULL;
	}
	return hr;
}

DllExport HRESULT TpmNVReadValue(
	UINT32 nvIndex,
	_Out_writes_to_opt_(cbData, *pcbResult) PBYTE pbData,
	UINT32 cbData,
	_Out_ PUINT32 pcbResult
	)
{
	HRESULT hr = 0;
	TBS_CONTEXT_PARAMS2 contextParams;
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	UINT32 tpmVersion;
	BYTE pbOwnerAuth[256] = { 0 };
	UINT32 cbOwnerAuth = 256;

	// Get TPM version to select implementation
	if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
	{
		goto Cleanup;
	}
	//get the tbs handle
	contextParams.version = TBS_CONTEXT_VERSION_TWO;
	contextParams.asUINT32 = 0;
	contextParams.includeTpm12 = 1;
	contextParams.includeTpm20 = 1;
	if (FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
	{
		goto Cleanup;
	}
	// get ownerAuth
	if (FAILED(hr = Tbsi_Get_OwnerAuth(hPlatformTbsHandle, TBS_OWNERAUTH_TYPE_FULL, pbOwnerAuth, &cbOwnerAuth))) {
		goto Cleanup;
	}

	if (tpmVersion == TPM_VERSION_12)
	{
		if (FAILED(hr = nvReadVaule12(hPlatformTbsHandle, nvIndex, pbOwnerAuth, cbOwnerAuth, pbData, cbData, pcbResult)))
		{
			goto Cleanup;
		}
		//wprintf(L"TPM nvdefine returned successfully!\n");
	}
	else if (tpmVersion == TPM_VERSION_20)
	{
		//Not implemented yet
	}
	else
	{
		hr = E_FAIL;
		goto Cleanup;
	}

Cleanup:
	// Close the TBS handle if we opened it in here
	if (hPlatformTbsHandle != NULL)
	{
		Tbsip_Context_Close(hPlatformTbsHandle);
		hPlatformTbsHandle = NULL;
	}
	return hr;
}

DllExport HRESULT TpmNVWriteValueAuth(
	UINT32 nvIndex,
	PBYTE nvAuth,
	UINT32 cbNvAuth,
	PBYTE pbData,
	UINT32 cbData
	)
{
	HRESULT hr = 0;
	TBS_CONTEXT_PARAMS2 contextParams;
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	UINT32 tpmVersion;

	// Get TPM version to select implementation
	if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
	{
		goto Cleanup;
	}
	//get the tbs handle
	contextParams.version = TBS_CONTEXT_VERSION_TWO;
	contextParams.asUINT32 = 0;
	contextParams.includeTpm12 = 1;
	contextParams.includeTpm20 = 1;
	if (FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
	{
		goto Cleanup;
	}

	if (tpmVersion == TPM_VERSION_12)
	{
		if (FAILED(hr = nvWriteVauleAuth12(hPlatformTbsHandle, nvIndex, nvAuth, cbNvAuth, pbData, cbData)))
		{
			goto Cleanup;
		}
		//wprintf(L"TPM nvdefine returned successfully!\n");
	}
	else if (tpmVersion == TPM_VERSION_20)
	{
		//Not implemented yet
	}
	else
	{
		hr = E_FAIL;
		goto Cleanup;
	}

Cleanup:
	// Close the TBS handle if we opened it in here
	if (hPlatformTbsHandle != NULL)
	{
		Tbsip_Context_Close(hPlatformTbsHandle);
		hPlatformTbsHandle = NULL;
	}
	return hr;
}

DllExport HRESULT TpmPCRExtend(
	UINT32 pcrIndex,
	PBYTE pbDigest,
	_Out_ PBYTE pbNewDigest
	)
{
	HRESULT hr = 0;
	TBS_CONTEXT_PARAMS2 contextParams;
	TBS_HCONTEXT hPlatformTbsHandle = 0;
	UINT32 tpmVersion;

	// Get TPM version to select implementation
	if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
	{
		goto Cleanup;
	}
	//get the tbs handle
	contextParams.version = TBS_CONTEXT_VERSION_TWO;
	contextParams.asUINT32 = 0;
	contextParams.includeTpm12 = 1;
	contextParams.includeTpm20 = 1;
	if (FAILED(hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&contextParams, &hPlatformTbsHandle)))
	{
		goto Cleanup;
	}

	if (tpmVersion == TPM_VERSION_12)
	{
		if (FAILED(hr = pcrExtend12(hPlatformTbsHandle, pcrIndex, pbDigest, pbNewDigest)))
		{
			goto Cleanup;
		}
		//wprintf(L"TPM nvdefine returned successfully!\n");
	}
	else if (tpmVersion == TPM_VERSION_20)
	{
		//Not implemented yet
	}
	else
	{
		hr = E_FAIL;
		goto Cleanup;
	}

Cleanup:
	// Close the TBS handle if we opened it in here
	if (hPlatformTbsHandle != NULL)
	{
		Tbsip_Context_Close(hPlatformTbsHandle);
		hPlatformTbsHandle = NULL;
	}
	return hr;
}