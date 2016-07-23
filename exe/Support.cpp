/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    Support.cpp

Author:

    Stefan Thom, stefanth@Microsoft.com, 2011/06/09

Abstract:

    Support functions for PCPTool that are not in direct relation for the SDK
    samples for the Platform Crypto Provider.

--*/

#include "stdafx.h"

EVENT_TYPE_DATA TcgId[] = {
    {SIPAEV_PREBOOT_CERT, L"EV_Preboot_Cert"},
    {SIPAEV_POST_CODE, L"EV_Post_Code"},
    {SIPAEV_UNUSED, L"EV_Unused"},
    {SIPAEV_NO_ACTION, L"EV_No_Action"},
    {SIPAEV_SEPARATOR, L"EV_Separator"},
    {SIPAEV_ACTION, L"EV_Action"},
    {SIPAEV_EVENT_TAG, L"EV_Event_Tag"},
    {SIPAEV_S_CRTM_CONTENTS, L"EV_CRTM_Contents"},
    {SIPAEV_S_CRTM_VERSION, L"EV_CRTM_Version"},
    {SIPAEV_CPU_MICROCODE, L"EV_CPU_Microcode"},
    {SIPAEV_PLATFORM_CONFIG_FLAGS, L"EV_Platform_Config_Flags"},
    {SIPAEV_TABLE_OF_DEVICES, L"EV_Table_Of_Devices"},
    {SIPAEV_COMPACT_HASH, L"EV_Compact_Hash"},
    {SIPAEV_IPL, L"EV_IPL"},
    {SIPAEV_IPL_PARTITION_DATA, L"EV_IPL_Partition_Data"},
    {SIPAEV_NONHOST_CODE, L"EV_NonHost_Code"},
    {SIPAEV_NONHOST_CONFIG, L"EV_NonHost_Config"},
    {SIPAEV_NONHOST_INFO, L"EV_NonHost_Info"},
    {SIPAEV_EFI_EVENT_BASE, L"EV_EFI_Event_Base"},
    {SIPAEV_EFI_VARIABLE_DRIVER_CONFIG, L"EV_EFI_Variable_Driver_Config"},
    {SIPAEV_EFI_VARIABLE_BOOT, L"EV_EFI_Variable_Boot"},
    {SIPAEV_EFI_BOOT_SERVICES_APPLICATION, L"EV_EFI_Boot_Services_Application"},
    {SIPAEV_EFI_BOOT_SERVICES_DRIVER, L"EV_EFI_Boot_Services_Driver"},
    {SIPAEV_EFI_RUNTIME_SERVICES_DRIVER, L"EV_EFI_Runtime_Services_Driver"},
    {SIPAEV_EFI_GPT_EVENT, L"EV_EFI_GPT_Event"},
    {SIPAEV_EFI_ACTION, L"EV_EFI_Action"},
    {SIPAEV_EFI_PLATFORM_FIRMWARE_BLOB, L"EV_EFI_Platform_Firmware_Blog"},
    {SIPAEV_EFI_HANDOFF_TABLES, L"EV_EFI_Handoff_Tables"},
    {0xFFFFFFFF, L"EV_Unknown"}
};

EVENT_TYPE_DATA SipaId[] = {
    {SIPAEVENT_TRUSTBOUNDARY, L"Trustboundary"},
    {SIPAEVENT_ELAM_AGGREGATION, L"ELAM_Aggregation"},
    {SIPAEVENT_LOADEDMODULE_AGGREGATION, L"LoadedModule_Aggregation"},
    {SIPAEVENT_TRUSTPOINT_AGGREGATION, L"TrustPoint_Aggregation"},
    {SIPAERROR_FIRMWAREFAILURE, L"FirmwareFailure"},
    {SIPAERROR_TPMFAILURE, L"TpmFailure"},
    {SIPAERROR_INTERNALFAILURE, L"InternalFailure"},
    {SIPAEVENT_INFORMATION, L"Information"},
    {SIPAEVENT_BOOTCOUNTER, L"BootCounter"},
    {SIPAEVENT_TRANSFER_CONTROL, L"Transfer_Control"},
    {SIPAEVENT_APPLICATION_RETURN, L"Application_Return"},
    {SIPAEVENT_BITLOCKER_UNLOCK, L"BitLocker_Unlock"},
    {SIPAEVENT_EVENTCOUNTER, L"EventCounter"},
    {SIPAEVENT_COUNTERID, L"CounterId"},
    {SIPAEVENT_BOOTDEBUGGING, L"BootDebug"},
    {SIPAEVENT_OSKERNELDEBUG, L"OsKernelDebug"},
    {SIPAEVENT_CODEINTEGRITY, L"CodeIntegrity"},
    {SIPAEVENT_TESTSIGNING, L"Testsigning"},
    {SIPAEVENT_DATAEXECUTIONPREVENTION, L"DataExecutionPrevention"},
    {SIPAEVENT_SAFEMODE, L"SafeMode"},
    {SIPAEVENT_WINPE, L"WinPE"},
    {SIPAEVENT_PHYSICALADDRESSEXTENSION, L"PhysicalAddressExtension"},
    {SIPAEVENT_OSDEVICE, L"OsDevice"},
    {SIPAEVENT_SYSTEMROOT, L"SystemRoot"},
    {SIPAEVENT_HYPERVISOR_LAUNCH_TYPE, L"HypervisorLaunchType"},
    {SIPAEVENT_HYPERVISOR_IOMMU_POLICY, L"HypervisorIOMMUPolicy"},
    {SIPAEVENT_HYPERVISOR_DEBUG, L"HypervisorDebug"},
    {SIPAEVENT_DRIVER_LOAD_POLICY, L"DriverLoadPolicy"},
    {SIPAEVENT_NOAUTHORITY, L"NoAuthority"},
    {SIPAEVENT_AUTHORITYPUBKEY, L"AuthorityPubKey"},
    {SIPAEVENT_FILEPATH, L"FilePath"},
    {SIPAEVENT_IMAGESIZE, L"ImageSize"},
    {SIPAEVENT_HASHALGORITHMID, L"HashAlgorithmId"},
    {SIPAEVENT_AUTHENTICODEHASH, L"AuthenticodeHash"},
    {SIPAEVENT_AUTHORITYISSUER, L"AuthorityIssuer"},
    {SIPAEVENT_AUTHORITYSERIAL, L"AuthoritySerial"},
    {SIPAEVENT_IMAGEBASE, L"ImageBase"},
    {SIPAEVENT_AUTHORITYPUBLISHER, L"AuthorityPublisher"},
    {SIPAEVENT_AUTHORITYSHA1THUMBPRINT, L"AuthoritySHA1Thumbprint"},
    {SIPAEVENT_IMAGEVALIDATED, L"ImageValidated"},
    {SIPAEVENT_QUOTE, L"Quote"},
    {SIPAEVENT_QUOTESIGNATURE, L"QuoteSignature"},
    {SIPAEVENT_AIKID, L"AikId"},
    {SIPAEVENT_AIKPUBDIGEST, L"AikPubDigest"},
    {SIPAEVENT_ELAM_KEYNAME, L"ELAM_KeyName"},
    {SIPAEVENT_ELAM_CONFIGURATION, L"ELAM_Configuration"},
    {SIPAEVENT_ELAM_POLICY, L"ELAM_Policy"},
    {SIPAEVENT_ELAM_MEASURED, L"ELAM_Measured"},
    {0xFFFFFFFF, L"Unknown"}
};

EVENT_TYPE_DATA OsDeviceId[] = {
    {OSDEVICE_TYPE_UNKNOWN, L"UNKNOWN"},
    {OSDEVICE_TYPE_BLOCKIO_HARDDISK, L"BLOCKIO_HARDDISK"},
    {OSDEVICE_TYPE_BLOCKIO_REMOVABLEDISK, L"BLOCKIO_REMOVABLEDISK"},
    {OSDEVICE_TYPE_BLOCKIO_CDROM, L"BLOCKIO_CDROM"},
    {OSDEVICE_TYPE_BLOCKIO_PARTITION, L"BLOCKIO_PARTITION"},
    {OSDEVICE_TYPE_BLOCKIO_FILE, L"BLOCKIO_FILE"},
    {OSDEVICE_TYPE_BLOCKIO_RAMDISK, L"BLOCKIO_RAMDISK"},
    {OSDEVICE_TYPE_BLOCKIO_VIRTUALHARDDISK, L"BLOCKIO_VIRTUALHARDDISK"},
    {OSDEVICE_TYPE_SERIAL, L"SERIAL"},
    {OSDEVICE_TYPE_UDP, L"UDP"},
    {0xFFFFFFFF, L"Unknown"}
};

EVENT_TYPE_DATA TransferControlId[] = {
    {0x00000000, L"NONE"},
    {0x00000001, L"OSLOADER"},
    {0x00000002, L"RESUME"},
    {0x00000003, L"MSUTILITY"},
    {0x00000004, L"NOSIGCHECK"},
    {0x00000005, L"HYPERVISOR"},
    {0xFFFFFFFF, L"Unknown"}
};

void
PcpToolLevelPrefix(
    UINT32 level
    )
{
    for(UINT32 n = 0; n < level; n++)
    {
        wprintf(L"  ");
    }
}

HRESULT
PcpToolDisplaySIPA(
    _In_reads_opt_(cbWBCL) PBYTE pbWBCL,
    UINT32 cbWBCL,
    UINT32 level
    )
{
    HRESULT hr = S_OK;
    PBYTE pbWBCLIntern = pbWBCL;
    UINT32 cbWBCLIntern = cbWBCL;
    UINT32 sipaType = 0;
    UINT32 cbSipaLen = 0;
    PBYTE pbSipaData = NULL;
    PWSTR eventStr = NULL;

    while(cbWBCLIntern > (2 * sizeof(UINT32)))
    {
        PWSTR eventEndStr = L"SipaEvent";

        sipaType = *((PUINT32)pbWBCLIntern);
        cbSipaLen = *((PUINT32)&pbWBCLIntern[sizeof(UINT32)]);
        if(cbWBCLIntern < (2 * sizeof(UINT32) + cbSipaLen))
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        if(cbSipaLen > 0)
        {
            pbSipaData = &pbWBCLIntern[2 * sizeof(UINT32)];
        }
        else
        {
            pbSipaData = NULL;
        }

        for(UINT32 n = 0; SipaId[n].Id != 0xFFFFFFFF; n++)
        {
            if(SipaId[n].Id == sipaType)
            {
                eventStr = SipaId[n].Name;
            }
        }

        PcpToolLevelPrefix(level);
        if(eventStr != NULL)
        {
            wprintf(L"<%s Size=\"%u\"%s>",
                    eventStr,
                    cbSipaLen,
                    (cbSipaLen == 0) ? L"/" : L"");
            eventEndStr = eventStr;
        }
        else
        {
            wprintf(L"<SipaEvent Type=\"0x%08x\" Size=\"%u\"%s>",
                    sipaType,
                    cbSipaLen,
                    (cbSipaLen == 0) ? L"/" : L"");
        }

        if(cbSipaLen > 0)
        {
            if((sipaType & (SIPAEVENTTYPE_AGGREGATION |
                            SIPAEVENTTYPE_CONTAINER)) == (SIPAEVENTTYPE_AGGREGATION |
                                                          SIPAEVENTTYPE_CONTAINER))
            {
                wprintf(L"\n");
                if(FAILED(hr = PcpToolDisplaySIPA(pbSipaData,
                                                  cbSipaLen,
                                                  level + 1)))
                {
                    goto Cleanup;
                }
                PcpToolLevelPrefix(level);
                wprintf(L"</%s>\n", eventEndStr);
            }
            else if((cbSipaLen == sizeof(BYTE)) &
                    ((sipaType == SIPAEVENT_BOOTDEBUGGING) ||
                     (sipaType == SIPAEVENT_OSKERNELDEBUG) ||
                     (sipaType == SIPAEVENT_CODEINTEGRITY) ||
                     (sipaType == SIPAEVENT_TESTSIGNING) ||
                     (sipaType == SIPAEVENT_WINPE) ||
                     (sipaType == SIPAEVENT_SAFEMODE) ||
                     (sipaType == SIPAEVENT_IMAGEVALIDATED) ||
                     (sipaType == SIPAEVENT_NOAUTHORITY)))
            {
                if(pbSipaData[0] == 0)
                {
                    wprintf(L"FALSE</%s>\n", eventEndStr);
                }
                else
                {
                    wprintf(L"TRUE</%s>\n", eventEndStr);
                }
            }
            else if((cbSipaLen == sizeof(UINT64)) &
                    ((sipaType == SIPAEVENT_IMAGESIZE) ||
                     (sipaType == SIPAEVENT_IMAGEBASE) ||
                     (sipaType == SIPAEVENT_HYPERVISOR_LAUNCH_TYPE) ||
                     (sipaType == SIPAEVENT_DATAEXECUTIONPREVENTION) ||
                     (sipaType == SIPAEVENT_PHYSICALADDRESSEXTENSION) ||
                     (sipaType == SIPAEVENT_BOOTCOUNTER) ||
                     (sipaType == SIPAEVENT_EVENTCOUNTER) ||
                     (sipaType == SIPAEVENT_COUNTERID)))
            {
                wprintf(L"%I64u<!-- 0x%016I64x --></%s>\n",
                        *((PUINT64)pbSipaData),
                        *((PUINT64)pbSipaData),
                        eventEndStr);
            }
            else if((sipaType == SIPAEVENT_FILEPATH) ||
                    (sipaType == SIPAEVENT_SYSTEMROOT) ||
                    (sipaType == SIPAEVENT_AUTHORITYPUBLISHER) ||
                    (sipaType == SIPAEVENT_AUTHORITYISSUER))
            {
                wprintf(L"%s</%s>\n", (PWCHAR)pbSipaData, eventEndStr);
            }
            else if((cbSipaLen == sizeof(UINT32)) &
                    (sipaType == SIPAEVENT_BITLOCKER_UNLOCK))
            {
                UINT32 dwBitLockerUnlock = *((PUINT32)pbSipaData);
                if(dwBitLockerUnlock == FVEB_UNLOCK_FLAG_NONE)
                {
                    wprintf(L"</%s>\n", eventEndStr);
                }
                else
                {
                    if(dwBitLockerUnlock & FVEB_UNLOCK_FLAG_CACHED)
                    {
                        wprintf(L"\n");
                        PcpToolLevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>CACHED</BitLockerKeyFlag>");
                    }
                    if(dwBitLockerUnlock & FVEB_UNLOCK_FLAG_MEDIA)
                    {
                        wprintf(L"\n");
                        PcpToolLevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>MEDIA</BitLockerKeyFlag>");
                    }
                    if(dwBitLockerUnlock & FVEB_UNLOCK_FLAG_TPM)
                    {
                        wprintf(L"\n");
                        PcpToolLevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>TPM</BitLockerKeyFlag>");
                    }
                    if(dwBitLockerUnlock & FVEB_UNLOCK_FLAG_PIN)
                    {
                        wprintf(L"\n");
                        PcpToolLevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>PIN</BitLockerKeyFlag>");
                    }
                    if(dwBitLockerUnlock & FVEB_UNLOCK_FLAG_EXTERNAL)
                    {
                        wprintf(L"\n");
                        PcpToolLevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>EXTERNAL</BitLockerKeyFlag>");
                    }
                    if(dwBitLockerUnlock & FVEB_UNLOCK_FLAG_RECOVERY)
                    {
                        wprintf(L"\n");
                        PcpToolLevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>RECOVERY</BitLockerKeyFlag>");
                    }
                    if(dwBitLockerUnlock & ~(FVEB_UNLOCK_FLAG_CACHED |
                                             FVEB_UNLOCK_FLAG_MEDIA |
                                             FVEB_UNLOCK_FLAG_TPM |
                                             FVEB_UNLOCK_FLAG_PIN |
                                             FVEB_UNLOCK_FLAG_EXTERNAL |
                                             FVEB_UNLOCK_FLAG_RECOVERY))
                    {
                        wprintf(L"\n");
                        PcpToolLevelPrefix(level + 1);
                        wprintf(L"<BitLockerKeyFlag>UNKNOWN</BitLockerKeyFlag>");
                    }
                    wprintf(L"\n");
                    PcpToolLevelPrefix(level);
                    wprintf(L"</%s>\n", eventEndStr);
                }
            }
            else if((cbSipaLen == sizeof(UINT32)) &
                    (sipaType == SIPAEVENT_OSDEVICE))
            {
                UINT32 dwOsDevice = *((PUINT32)pbSipaData);
                UINT32 n = 0;
                for(n = 0; OsDeviceId[n].Id != 0xFFFFFFFF; n++)
                {
                    if(OsDeviceId[n].Id == dwOsDevice)
                    {
                        break;
                    }
                }
                wprintf(L"%s</%s>\n",
                        OsDeviceId[n].Name, eventEndStr);
            }
            else if((cbSipaLen == sizeof(UINT32)) &
                    (sipaType == SIPAEVENT_DRIVER_LOAD_POLICY))
            {
                UINT32 dwDriverLoadPolicy = *((PUINT32)pbSipaData);
                if(dwDriverLoadPolicy == 0x00000001)
                {
                    wprintf(L"DEFAULT</%s>\n", eventEndStr);
                }
                else
                {
                    wprintf(L"%u</%s>\n",
                        dwDriverLoadPolicy, eventEndStr);
                }
            }
            else if((cbSipaLen == sizeof(UINT32)) &
                    (sipaType == SIPAEVENT_TRANSFER_CONTROL))
            {
                UINT32 dwTransferControl = *((PUINT32)pbSipaData);
                UINT32 n = 0;
                for(n = 0; TransferControlId[n].Id != 0xFFFFFFFF; n++)
                {
                    if(TransferControlId[n].Id == dwTransferControl)
                    {
                        break;
                    }
                }
                wprintf(L"%s</%s>\n",
                        TransferControlId[n].Name, eventEndStr);
            }
            else if((cbSipaLen == sizeof(UINT32)) &
                    (sipaType == SIPAEVENT_HASHALGORITHMID))
            {
                UINT32 dwAlgId = *((PUINT32)pbSipaData);
                switch(dwAlgId)
                {
                    case CALG_MD4:
                        wprintf(L"MD4</%s>\n", eventEndStr);
                        break;
                    case CALG_MD5:
                        wprintf(L"MD5/%s>\n", eventEndStr);
                        break;
                    case CALG_SHA1:
                        wprintf(L"SHA-1</%s>\n", eventEndStr);
                        break;
                    case CALG_SHA_256:
                        wprintf(L"SHA-256</%s>\n", eventEndStr);
                        break;
                    case CALG_SHA_384:
                        wprintf(L"SHA-384</%s>\n", eventEndStr);
                        break;
                    case CALG_SHA_512:
                        wprintf(L"SHA-512</%s>\n", eventEndStr);
                        break;
                    default:
                        wprintf(L"%u<!-- 0x%08x --></%s>\n",
                                *((PUINT32)pbSipaData),
                                *((PUINT32)pbSipaData),
                                eventEndStr);
                        break;
                }
            }
            else
            {
                wprintf(L"\n");
                PcpToolLevelPrefix(level + 1);
                for(UINT32 n = 0; n < cbSipaLen; n++)
                {
                    wprintf(L"%02x", pbSipaData[n]);
                }
                wprintf(L"\n");
                PcpToolLevelPrefix(level + 1);
                wprintf(L"<!-- ");
                for(UINT32 n = 0; n < cbSipaLen; n++)
                {
                    if(((pbSipaData[n] >= '0') && (pbSipaData[n] <= '9')) ||
                       ((pbSipaData[n] >= 'A') && (pbSipaData[n] <= 'Z')) ||
                       ((pbSipaData[n] >= 'a') && (pbSipaData[n] <= 'z')))
                    {
                        wprintf(L"%c", pbSipaData[n]);
                    }
                    else
                    {
                        wprintf(L".");
                    }
                }
                wprintf(L" -->\n");
                PcpToolLevelPrefix(level);
                wprintf(L"</%s>\n", eventEndStr);
            }
        }

        if(cbWBCLIntern >= (2 * sizeof(UINT32) + cbSipaLen))
        {
            pbWBCLIntern += (2 * sizeof(UINT32) + cbSipaLen);
            cbWBCLIntern -= (2 * sizeof(UINT32) + cbSipaLen);
        }
        else
        {
            break;
        }
    }

Cleanup:
    return hr;
}

HRESULT
PcpToolDisplayLog(
    _In_reads_opt_(cbWBCL) PBYTE pbWBCL,
    UINT32 cbWBCL,
    UINT32 level
    )
{
    HRESULT hr = S_OK;
    PTCG_PCClientPCREventStruct pEntry = NULL;
    BYTE extendBuffer[40] = {0};
    BYTE softPCR[24][20] = {
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[00]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[01]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[02]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[03]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[04]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[05]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[06]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[07]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[08]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[09]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[10]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[11]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[12]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[13]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[14]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[15]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, //PCR[16]
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, //PCR[17]
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, //PCR[18]
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, //PCR[19]
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, //PCR[20]
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, //PCR[21]
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}, //PCR[22]
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};//PCR[23]}
    BOOLEAN usedPcr[24] = {0};
    UINT32 result = 0;

    // Parameter check
    if((pbWBCL == NULL) ||
       (cbWBCL < sizeof(TCG_PCClientPCREventStruct)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    PcpToolLevelPrefix(level);
    wprintf(L"<TCGLog>\n");
    PcpToolLevelPrefix(level + 1);
    wprintf(L"<WBCL size=\"%u\">\n", cbWBCL);
    for(pEntry = (PTCG_PCClientPCREventStruct)pbWBCL;
        ((PBYTE)pEntry - pbWBCL + sizeof(TCG_PCClientPCREventStruct) -
                                sizeof(BYTE)) < cbWBCL;
        pEntry = (PTCG_PCClientPCREventStruct) (((PBYTE)pEntry) +
                           sizeof(TCG_PCClientPCREventStruct) -
                           sizeof(BYTE) +
                           pEntry->eventDataSize))
    {
        ULONG cbEntry = sizeof(TCG_PCClientPCREventStruct) -
                        sizeof(BYTE) +
                        pEntry->eventDataSize;
        BOOLEAN digestMatchesData = FALSE;
        BYTE eventDataDigest[20] = {0};
        WCHAR digestStr[42] = L"";
        PWSTR eventStr = NULL;

        // Ensure that the have a valid entry
        if(((PBYTE)pEntry - pbWBCL + cbEntry) > cbWBCL)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        for(UINT32 n = 0; TcgId[n].Id != 0xFFFFFFFF; n++)
        {
            if(TcgId[n].Id == pEntry->eventType)
            {
                eventStr = TcgId[n].Name;
            }
        }

        PWSTR digestStringIndex = digestStr;
        size_t cchDigestSrting = sizeof(digestStr) / sizeof(WCHAR);
        for(UINT32 n = 0; n < sizeof(pEntry->digest.data); n++)
        {
            if(FAILED(hr = StringCchPrintfExW(
                                digestStringIndex,
                                cchDigestSrting,
                                &digestStringIndex,
                                &cchDigestSrting,
                                0,
                                L"%02x",
                                pEntry->digest.data[n])))
            {
                goto Cleanup;
            }
        }

        // Validate the event digest
        if(FAILED(hr = TpmAttiShaHash(
                                BCRYPT_SHA1_ALGORITHM,
                                NULL,
                                0,
                                pEntry->event,
                                pEntry->eventDataSize,
                                eventDataDigest,
                                sizeof(eventDataDigest),
                                &result)))
        {
            goto Cleanup;
        }
        digestMatchesData = (memcmp(eventDataDigest,
                                    pEntry->digest.data,
                                    sizeof(pEntry->digest.data)) == 0);

        PcpToolLevelPrefix(level + 2);
        if(eventStr != NULL)
        {
            wprintf(L"<%s PCR=\"%02i\" %sDigest=\"%s\" Size=\"%u\"%s>\n",
                    eventStr,
                    pEntry->pcrIndex,
                    digestMatchesData?L"Event":L"",
                    digestStr,
                    pEntry->eventDataSize,
                    (pEntry->eventDataSize == 0) ? L"/" : L"");
        }
        else
        {
            wprintf(L"<TCGEvent Type=\"%08x\" PCR=\"%02i\" %sDigest=\"%s\" Size=\"%u\"%s>\n",
                    pEntry->eventType,
                    pEntry->pcrIndex,
                    digestMatchesData?L"Event":L"",
                    digestStr,
                    pEntry->eventDataSize,
                    (pEntry->eventDataSize == 0) ? L"/" : L"");
        }

        // Decode SIPA events
        if((((pEntry->pcrIndex >= 12) &&
             (pEntry->pcrIndex <= 14)) ||
            (pEntry->pcrIndex == 0xffffffff))&&
           ((pEntry->eventType == EV_EVENT_TAG) ||
            (pEntry->eventType == EV_NO_ACTION)))
        {
            if(FAILED(hr = PcpToolDisplaySIPA(
                                    pEntry->event,
                                    pEntry->eventDataSize,
                                    level + 3)))
            {
                goto Cleanup;
            }
        }
        else
        {
            if(pEntry->eventDataSize > 0)
            {
                PcpToolLevelPrefix(level + 3);
                for(UINT32 n = 0; n < pEntry->eventDataSize; n++)
                {
                    wprintf(L"%02x", pEntry->event[n]);
                }
                wprintf(L"\n");
                PcpToolLevelPrefix(level + 3);
                wprintf(L"<!-- ");
                for(UINT32 n = 0; n < pEntry->eventDataSize; n++)
                {
                    if(((pEntry->event[n] >= '0') && (pEntry->event[n] <= '9')) ||
                       ((pEntry->event[n] >= 'A') && (pEntry->event[n] <= 'Z')) ||
                       ((pEntry->event[n] >= 'a') && (pEntry->event[n] <= 'z')))
                    {
                        wprintf(L"%c", pEntry->event[n]);
                    }
                    else
                    {
                        wprintf(L".");
                    }
                }
                wprintf(L" -->\n");
            }
        }
        PcpToolLevelPrefix(level + 2);
        if(pEntry->eventDataSize > 0)
        {
            if(eventStr != NULL)
            {
                wprintf(L"</%s>\n", eventStr);
            }
            else
            {
                wprintf(L"</TCGEvent>\n");
            }
        }

        if(pEntry->pcrIndex < 24)
        {
            if(memcpy_s(extendBuffer, sizeof(extendBuffer), softPCR[pEntry->pcrIndex], 20))
            {
                hr = E_FAIL;
                goto Cleanup;
            }
            if(memcpy_s(&extendBuffer[20], sizeof(extendBuffer) - 20, pEntry->digest.data, 20))
            {
                hr = E_FAIL;
                goto Cleanup;
            }
            if(FAILED(hr = TpmAttiShaHash(
                                BCRYPT_SHA1_ALGORITHM,
                                NULL,
                                0,
                                extendBuffer,
                                sizeof(extendBuffer),
                                softPCR[pEntry->pcrIndex],
                                sizeof(softPCR[pEntry->pcrIndex]),
                                &result)))
            {
                goto Cleanup;
            }
            usedPcr[pEntry->pcrIndex] = TRUE;
        }
    }
    PcpToolLevelPrefix(level + 1);
    wprintf(L"</WBCL>\n");
    PcpToolLevelPrefix(level + 1);
    wprintf(L"<PCRs>\n");
    for(UINT32 n = 0; n < 24; n++)
    {
        if(usedPcr[n] != FALSE)
        {
            PcpToolLevelPrefix(level + 2);
            wprintf(L"<PCR Index=\"%02u\">", n);
            for(UINT32 m = 0; m < 20; m++)
            {
                    wprintf(L"%02x", softPCR[n][m]);
            }
            wprintf(L"</PCR>\n");
        }
    }
    PcpToolLevelPrefix(level + 1);
    wprintf(L"</PCRs>\n");
    PcpToolLevelPrefix(level);
    wprintf(L"</TCGLog>\n");

Cleanup:
    return hr;
}

HRESULT
PcpToolDisplayKey(
    _In_ PCWSTR lpKeyName,
    _In_reads_(cbKey) PBYTE pbKey,
    DWORD cbKey,
    UINT32 level
    )
{
    HRESULT hr = S_OK;
    BCRYPT_RSAKEY_BLOB* pKey = (BCRYPT_RSAKEY_BLOB*)pbKey;
    BYTE pubKeyDigest[20] = {0};
    UINT32 cbRequired = 0;

    // Parameter check
    if((pbKey == NULL) ||
       (cbKey < sizeof(BCRYPT_RSAKEY_BLOB)) ||
       (cbKey < (sizeof(BCRYPT_RSAKEY_BLOB) +
                 pKey->cbPublicExp +
                 pKey->cbModulus +
                 pKey->cbPrime1 +
                 pKey->cbPrime2)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    if(FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                  NULL,
                                  0,
                                  &pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
                                         pKey->cbPublicExp],
                                  pKey->cbModulus,
                                  pubKeyDigest,
                                  sizeof(pubKeyDigest),
                                  &cbRequired)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    PcpToolLevelPrefix(level);
    wprintf(L"<RSAKey size=\"%u\"", cbKey);
    if((lpKeyName != NULL) &&
       (wcsnlen_s(lpKeyName, 2097) != 0))
    {
        wprintf(L" keyName=\"%s\"", lpKeyName);
    }
    wprintf(L">\n");

    PcpToolLevelPrefix(level + 1);
    wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
           ((PBYTE)&pKey->Magic)[0],
           ((PBYTE)&pKey->Magic)[1],
           ((PBYTE)&pKey->Magic)[2],
           ((PBYTE)&pKey->Magic)[3],
           pKey->Magic);

    PcpToolLevelPrefix(level + 1);
    wprintf(L"<BitLength>%u</BitLength>\n", pKey->BitLength);

    PcpToolLevelPrefix(level + 1);
    wprintf(L"<PublicExp size=\"%u\">\n", pKey->cbPublicExp);
    PcpToolLevelPrefix(level + 2);
    for(UINT32 n = 0; n < pKey->cbPublicExp; n++)
    {
        wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) + n]);
    }
    wprintf(L"\n");
    PcpToolLevelPrefix(level + 1);
    wprintf(L"</PublicExp>\n");

    PcpToolLevelPrefix(level + 1);
    wprintf(L"<Modulus size=\"%u\" digest=\"", pKey->cbModulus);
    for(UINT32 n = 0; n < sizeof(pubKeyDigest); n++)
    {
        wprintf(L"%02x", pubKeyDigest[n]);
    }
    wprintf(L"\">\n", pKey->cbModulus);
    PcpToolLevelPrefix(level + 2);
    for(UINT32 n = 0; n < pKey->cbModulus; n++)
    {
        wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
                               pKey->cbPublicExp +
                               n]);
    }
    wprintf(L"\n");
    PcpToolLevelPrefix(level + 1);
    wprintf(L"</Modulus>\n");

    PcpToolLevelPrefix(level + 1);
    if(pKey->cbPrime1 == 0)
    {
        wprintf(L"<Prime1/>\n");
    }
    else
    {
        wprintf(L"<Prime1 size=\"%u\">\n", pKey->cbPrime1);
        PcpToolLevelPrefix(level + 2);
        for(UINT32 n = 0; n < pKey->cbPrime1; n++)
        {
            wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
                                   pKey->cbPublicExp +
                                   pKey->cbModulus +
                                   n]);
        }
        wprintf(L"\n");
        PcpToolLevelPrefix(level + 1);
        wprintf(L"</Prime1>\n");
    }
    PcpToolLevelPrefix(level + 1);
    if(pKey->cbPrime2 == 0)
    {
        wprintf(L"<Prime2/>\n");
    }
    else
    {
        wprintf(L"<Prime2 size=\"%u\">\n", pKey->cbPrime2);
        PcpToolLevelPrefix(level + 2);
        for(UINT32 n = 0; n < pKey->cbPrime2; n++)
        {
            wprintf(L"%02x", pbKey[sizeof(BCRYPT_RSAKEY_BLOB) +
                                   pKey->cbPublicExp +
                                   pKey->cbModulus +
                                   pKey->cbPrime1 +
                                   n]);
        }
        wprintf(L"\n");
        PcpToolLevelPrefix(level + 1);
        wprintf(L"</Prime2>\n");
    }
    PcpToolLevelPrefix(level);
    wprintf(L"</RSAKey>\n");

Cleanup:
    return hr;
}

HRESULT
PcpToolDisplayPlatformAttestation(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    DWORD cbAttestation,
    UINT32 level
    )
{
    HRESULT hr = S_OK;
    PPCP_PLATFORM_ATTESTATION_BLOB pAttestation = (PPCP_PLATFORM_ATTESTATION_BLOB)pbAttestation;
    UINT32 cursor = 0;

    // Parameter check
    if((pbAttestation == NULL) ||
       (cbAttestation < sizeof(PCP_PLATFORM_ATTESTATION_BLOB)) ||
       (pAttestation->Magic != PCP_PLATFORM_ATTESTATION_MAGIC) ||
       (cbAttestation < (pAttestation->HeaderSize +
                         pAttestation->cbPcrValues +
                         pAttestation->cbQuote +
                         pAttestation->cbSignature +
                         pAttestation->cbLog)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    PcpToolLevelPrefix(level);
    wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
           ((PBYTE)&pAttestation->Magic)[0],
           ((PBYTE)&pAttestation->Magic)[1],
           ((PBYTE)&pAttestation->Magic)[2],
           ((PBYTE)&pAttestation->Magic)[3],
           pAttestation->Magic);

    PcpToolLevelPrefix(level);
    if(pAttestation->Platform == TPM_VERSION_12)
    {
        wprintf(L"<Platform>TPM_VERSION_12</Platform>\n");
    }
    else if(pAttestation->Platform == TPM_VERSION_20)
    {
        wprintf(L"<Platform>TPM_VERSION_20</Platform>\n");
    }
    else
    {
        wprintf(L"<Platform>0x%08x</Platform>\n", pAttestation->Platform);
    }

    PcpToolLevelPrefix(level);
    wprintf(L"<HeaderSize>%u</HeaderSize>\n", pAttestation->HeaderSize);

    PcpToolLevelPrefix(level);
    wprintf(L"<PcrValues size=\"%u\">\n", pAttestation->cbPcrValues);
    cursor = pAttestation->HeaderSize;
    for(UINT32 n = 0; n < (pAttestation->cbPcrValues / 20); n++)
    {
        PcpToolLevelPrefix(level + 1);
        wprintf(L"<PCR Index=\"%u\">", n);
        for(UINT32 m = 0; m < 20; m++)
        {
            wprintf(L"%02x", pbAttestation[cursor]);
            cursor++;
        }
        wprintf(L"</PCR>\n");
    }
    PcpToolLevelPrefix(level);
    wprintf(L"</PcrValues>\n");

    PcpToolLevelPrefix(level);
    wprintf(L"<Quote size=\"%u\">\n", pAttestation->cbQuote);
    PcpToolLevelPrefix(level + 1);
    for(UINT32 n = 0; n < pAttestation->cbQuote; n++)
    {
        wprintf(L"%02x", pbAttestation[cursor]);
        cursor++;
    }
    wprintf(L"\n");
    PcpToolLevelPrefix(level);
    wprintf(L"</Quote>\n");

    PcpToolLevelPrefix(level);
    wprintf(L"<Signature size=\"%u\">\n", pAttestation->cbSignature);
    PcpToolLevelPrefix(level + 1);
    for(UINT32 n = 0; n < pAttestation->cbSignature; n++)
    {
        wprintf(L"%02x", pbAttestation[cursor]);
        cursor++;
    }
    wprintf(L"\n");
    PcpToolLevelPrefix(level);
    wprintf(L"</Signature>\n");

    PcpToolLevelPrefix(level);
    wprintf(L"<Log size=\"%u\">\n", pAttestation->cbLog);
    if(FAILED(hr = PcpToolDisplayLog(&pbAttestation[cursor], pAttestation->cbLog, level + 2)))
    {
        goto Cleanup;
    }
    PcpToolLevelPrefix(level);
    wprintf(L"</Log>\n");

Cleanup:
    return hr;
}

HRESULT
PcpToolDisplayKeyBlob(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    DWORD cbKeyBlob,
    UINT32 level
    )
{
    HRESULT hr = S_OK;
    PPCP_KEY_BLOB p12Key = (PPCP_KEY_BLOB)pbKeyBlob;
    PPCP_KEY_BLOB_WIN8 pW8Key = (PPCP_KEY_BLOB_WIN8)pbKeyBlob;
    UINT32 cursor = 0;
    PWSTR pcpTypeString[] = {L"PCPTYPE_UNKNOWN",
                             L"PCPTYPE_TPM12",
                             L"PCPTYPE_TPM20"};

    if((p12Key != NULL) &&
       (cbKeyBlob >= sizeof(PCP_KEY_BLOB)) &&
       (p12Key->magic == BCRYPT_PCP_KEY_MAGIC) &&
       (p12Key->cbHeader >= sizeof(PCP_KEY_BLOB)) &&
       (p12Key->pcpType == PCPTYPE_TPM12) &&
       (cbKeyBlob >= p12Key->cbHeader +
                     p12Key->cbTpmKey))
    {
        // TPM 1.2 Key
        PcpToolLevelPrefix(level);
        wprintf(L"<BCRYPT_KEY_BLOB size=\"%u\" sizeHdr=\"%u\">\n", cbKeyBlob, p12Key->cbHeader);
        PcpToolLevelPrefix(level + 1);
        wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
                ((PBYTE)&p12Key->magic)[0],
                ((PBYTE)&p12Key->magic)[1],
                ((PBYTE)&p12Key->magic)[2],
                ((PBYTE)&p12Key->magic)[3],
                p12Key->magic);
        PcpToolLevelPrefix(level + 1);
        wprintf(L"<pcpType>%s</pcpType>\n", (p12Key->pcpType < ARRAYSIZE(pcpTypeString)) ? pcpTypeString[p12Key->pcpType] : pcpTypeString[0]);
        PcpToolLevelPrefix(level + 1);
        wprintf(L"<flags>%08x</flags>\n", p12Key->flags);
        PcpToolLevelPrefix(level + 1);
        cursor += p12Key->cbHeader;
        wprintf(L"<TPM_KEY12 size=\"%u\">\n", p12Key->cbTpmKey);
        PcpToolLevelPrefix(level + 2);
        for(UINT32 n = 0; n < cbKeyBlob - cursor; n++)
        {
            wprintf(L"%02x", pbKeyBlob[cursor]);
            cursor++;
        }
        wprintf(L"\n");
        PcpToolLevelPrefix(level + 1);
        wprintf(L"</TPM_KEY12>\n");
        PcpToolLevelPrefix(level);
        wprintf(L"</BCRYPT_KEY_BLOB>\n");
    }
    else if((pW8Key != NULL) &&
            (cbKeyBlob >= sizeof(PCP_KEY_BLOB_WIN8)) &&
            (pW8Key->magic == BCRYPT_PCP_KEY_MAGIC) &&
            (pW8Key->cbHeader >= sizeof(PCP_KEY_BLOB_WIN8)) &&
            (pW8Key->pcpType == PCPTYPE_TPM20) &&
            (cbKeyBlob >= pW8Key->cbHeader +
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
        // TPM 2.0 Key
        PcpToolLevelPrefix(level);
        wprintf(L"<PCP_KEY_BLOB_WIN8 size=\"%u\" sizeHdr=\"%u\">\n", cbKeyBlob, pW8Key->cbHeader);
        PcpToolLevelPrefix(level + 1);
        wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
                ((PBYTE)&pW8Key->magic)[0],
                ((PBYTE)&pW8Key->magic)[1],
                ((PBYTE)&pW8Key->magic)[2],
                ((PBYTE)&pW8Key->magic)[3],
                pW8Key->magic);
        PcpToolLevelPrefix(level + 1);
        wprintf(L"<pcpType>%s</pcpType>\n", (p12Key->pcpType < ARRAYSIZE(pcpTypeString)) ? pcpTypeString[p12Key->pcpType] : pcpTypeString[0]);
        PcpToolLevelPrefix(level + 1);
        wprintf(L"<flags>%08x</flags>\n", pW8Key->flags);
        PcpToolLevelPrefix(level + 1);
        wprintf(L"<TPM2B_PUBLIC_KEY size=\"%u\">\n", pW8Key->cbPublic);
        cursor += pW8Key->cbHeader;

        if(pW8Key->cbPublic != 0)
        {
            PcpToolLevelPrefix(level + 2);
            for(UINT32 n = 0; n < pW8Key->cbPublic; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            PcpToolLevelPrefix(level + 1);
            wprintf(L"</TPM2B_PUBLIC_KEY>\n");
            cursor += pW8Key->cbPublic;
        }
        else
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_PUBLIC_KEY/>\n");
        }

        if(pW8Key->cbPrivate != 0)
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_KEY size=\"%u\">\n", pW8Key->cbPrivate);
            PcpToolLevelPrefix(level + 2);
            for(UINT32 n = 0; n < pW8Key->cbPrivate; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            PcpToolLevelPrefix(level + 1);
            wprintf(L"</TPM2B_PRIVATE_KEY>\n");
            cursor += pW8Key->cbPublic;
        }
        else
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_KEY/>\n");
        }

        if(pW8Key->cbMigrationPublic != 0)
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_PUBLIC_MIGRATION size=\"%u\">\n", pW8Key->cbMigrationPublic);
            PcpToolLevelPrefix(level + 2);
            for(UINT32 n = 0; n < pW8Key->cbMigrationPublic; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            PcpToolLevelPrefix(level + 1);
            wprintf(L"</TPM2B_PUBLIC_MIGRATION>\n");
            cursor += pW8Key->cbMigrationPublic;
        }
        else
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_PUBLIC_MIGRATION/>\n");
        }

        if(pW8Key->cbMigrationPrivate > 0)
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_MIGRATION size=\"%u\">\n", pW8Key->cbMigrationPrivate);
            PcpToolLevelPrefix(level + 2);
            for(UINT32 n = 0; n < pW8Key->cbMigrationPrivate; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            PcpToolLevelPrefix(level + 1);
            wprintf(L"</TPM2B_PRIVATE_MIGRATION>\n");
            cursor += pW8Key->cbMigrationPrivate;
        }
        else
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_MIGRATION/>\n");
        }

        if(pW8Key->cbPolicyDigestList > 0)
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPML_DIGEST_POLICY size=\"%u\">\n", pW8Key->cbPolicyDigestList);
            PcpToolLevelPrefix(level + 2);
            for(UINT32 n = 0; n < pW8Key->cbPolicyDigestList; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            PcpToolLevelPrefix(level + 1);
            wprintf(L"</TPML_DIGEST_POLICY>\n");
            cursor += pW8Key->cbPolicyDigestList;
        }
        else
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPML_DIGEST_POLICY/>\n");
        }

        if(pW8Key->cbPCRBinding > 0)
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<PcrBinding size=\"%u\">\n", pW8Key->cbPCRBinding);
            PcpToolLevelPrefix(level + 2);
            for(UINT32 n = 0; n < pW8Key->cbPCRBinding; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            PcpToolLevelPrefix(level + 1);
            wprintf(L"</PcrBinding>\n");
            cursor += pW8Key->cbPCRBinding;
        }
        else
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<PcrBinding/>\n");
        }

        if(pW8Key->cbPCRDigest > 0)
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<PcrDigest size=\"%u\">\n", pW8Key->cbPCRDigest);
            PcpToolLevelPrefix(level + 2);
            for(UINT32 n = 0; n < pW8Key->cbPCRDigest; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            PcpToolLevelPrefix(level + 1);
            wprintf(L"</PcrDigest>\n");
            cursor += pW8Key->cbPCRDigest;
        }
        else
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<PcrDigest/>\n");
        }

        if(pW8Key->cbEncryptedSecret > 0)
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_DATA_IMPORT_SECRET size=\"%u\">\n", pW8Key->cbEncryptedSecret);
            PcpToolLevelPrefix(level + 2);
            for(UINT32 n = 0; n < pW8Key->cbEncryptedSecret; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            PcpToolLevelPrefix(level + 1);
            wprintf(L"</TPM2B_DATA_IMPORT_SECRET>\n");
            cursor += pW8Key->cbEncryptedSecret;
        }
        else
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_DATA_IMPORT_SECRET/>\n");
        }

        if(pW8Key->cbTpm12HostageBlob > 0)
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_IMPORT size=\"%u\">\n", pW8Key->cbTpm12HostageBlob);
            PcpToolLevelPrefix(level + 2);
            for(UINT32 n = 0; n < pW8Key->cbTpm12HostageBlob; n++)
            {
                wprintf(L"%02x", pbKeyBlob[cursor + n]);
            }
            wprintf(L"\n");
            PcpToolLevelPrefix(level + 1);
            wprintf(L"</TPM2B_PRIVATE_IMPORT>\n");
            cursor += pW8Key->cbTpm12HostageBlob;
        }
        else
        {
            PcpToolLevelPrefix(level + 1);
            wprintf(L"<TPM2B_PRIVATE_IMPORT/>\n");
        }

        PcpToolLevelPrefix(level);
        wprintf(L"</PCP_KEY_BLOB_WIN8>\n");
    }
    else
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

Cleanup:
    return hr;
}

HRESULT
PcpToolDisplayKeyAttestation(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    DWORD cbAttestation,
    UINT32 level
    )
{
    HRESULT hr = S_OK;
    PPCP_KEY_ATTESTATION_BLOB pAttestation = (PPCP_KEY_ATTESTATION_BLOB)pbAttestation;
    UINT32 cursor = 0;

    // Parameter check
    if((pbAttestation == NULL) ||
       (cbAttestation < sizeof(PCP_KEY_ATTESTATION_BLOB)) ||
       (pAttestation->Magic != PCP_KEY_ATTESTATION_MAGIC) ||
       (cbAttestation < (pAttestation->HeaderSize +
                         pAttestation->cbKeyAttest +
                         pAttestation->cbSignature +
                         pAttestation->cbKeyBlob)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    PcpToolLevelPrefix(level);
    wprintf(L"<Magic>%c%c%c%c<!-- 0x%08x --></Magic>\n",
           ((PBYTE)&pAttestation->Magic)[0],
           ((PBYTE)&pAttestation->Magic)[1],
           ((PBYTE)&pAttestation->Magic)[2],
           ((PBYTE)&pAttestation->Magic)[3],
           pAttestation->Magic);

    PcpToolLevelPrefix(level);
    if(pAttestation->Platform == TPM_VERSION_12)
    {
        wprintf(L"<Platform>TPM_VERSION_12</Platform>\n");
    }
    else if(pAttestation->Platform == TPM_VERSION_20)
    {
        wprintf(L"<Platform>TPM_VERSION_20</Platform>\n");
    }
    else
    {
        wprintf(L"<Platform>0x%08x</Platform>\n", pAttestation->Platform);
    }

    PcpToolLevelPrefix(level);
    wprintf(L"<HeaderSize>%u</HeaderSize>\n", pAttestation->HeaderSize);
    cursor += pAttestation->HeaderSize;

    PcpToolLevelPrefix(level);
    wprintf(L"<Certify size=\"%u\">\n", pAttestation->cbKeyAttest);
    PcpToolLevelPrefix(level + 1);
    for(UINT32 n = 0; n < pAttestation->cbKeyAttest; n++)
    {
        wprintf(L"%02x", pbAttestation[cursor]);
        cursor++;
    }
    wprintf(L"\n");
    PcpToolLevelPrefix(level);
    wprintf(L"</Certify>\n");

    PcpToolLevelPrefix(level);
    wprintf(L"<Signature size=\"%u\">\n", pAttestation->cbSignature);
    PcpToolLevelPrefix(level + 1);
    for(UINT32 n = 0; n < pAttestation->cbSignature; n++)
    {
        wprintf(L"%02x", pbAttestation[cursor]);
        cursor++;
    }
    wprintf(L"\n");
    PcpToolLevelPrefix(level);
    wprintf(L"</Signature>\n");

    PcpToolLevelPrefix(level);
    wprintf(L"<KeyBlob size=\"%u\">\n", pAttestation->cbKeyBlob);
    if(FAILED(hr = PcpToolDisplayKeyBlob(&pbAttestation[cursor], pAttestation->cbKeyBlob, level + 1)))
    {
        goto Cleanup;
    }
    PcpToolLevelPrefix(level);
    wprintf(L"</KeyBlob>\n");

Cleanup:
    return hr;
}

HRESULT
PcpToolWriteFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData
    )
{
    HRESULT hr = S_OK;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD bytesWritten = 0;

    hFile = CreateFileW(
                lpFileName,
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                0);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }


    while(cbData > bytesWritten)
    {
        DWORD bytesWrittenLast = 0;
        if(!WriteFile(hFile,
                      &pbData[bytesWritten],
                      (DWORD)(cbData - bytesWritten),
                      &bytesWrittenLast,
                      NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
        bytesWritten += bytesWrittenLast;
    }

Cleanup:
    if(hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return hr;
}

HRESULT
PcpToolAppendFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData
    )
{
    HRESULT hr = S_OK;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD bytesWritten = 0;

    hFile = CreateFileW(
                lpFileName,
                GENERIC_WRITE,
                0,
                NULL,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                0);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if(SetFilePointer(hFile, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    while(cbData > bytesWritten)
    {
        DWORD bytesWrittenLast = 0;
        if(!WriteFile(hFile,
                      &pbData[bytesWritten],
                      (DWORD)(cbData - bytesWritten),
                      &bytesWrittenLast,
                      NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
        bytesWritten += bytesWrittenLast;
    }

Cleanup:
    if(hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return hr;
}

HRESULT
PcpToolReadFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData,
    __out PUINT32 pcbData
    )
{
    HRESULT hr = S_OK;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER dataSize = {0};
    DWORD bytesRead = 0;

    if(pcbData == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    hFile = CreateFileW(
                    lpFileName,
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if(!GetFileSizeEx(hFile, &dataSize))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if(dataSize.HighPart != 0)
    {
        hr = NTE_BAD_DATA;
        goto Cleanup;
    }

    *pcbData = dataSize.LowPart;
    if((pbData == NULL) || (cbData == 0))
    {
        goto Cleanup;
    }
    else if(cbData < *pcbData)
    {
        hr = NTE_BUFFER_TOO_SMALL;
        goto Cleanup;
    }
    else
    {
        while(cbData > bytesRead)
        {
            DWORD bytesReadLast = 0;
            if(!ReadFile(hFile,
                         &pbData[bytesRead],
                         (DWORD)(cbData - bytesRead),
                         &bytesReadLast,
                         NULL))
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                goto Cleanup;
            }
            bytesRead += bytesReadLast;
        }
    }

Cleanup:
    if(hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return hr;
}

HRESULT
PcpToolReadFile(
    _In_ PCWSTR lpFileName,
    UINT32 offset,
    _In_reads_(cbData) PBYTE pbData,
    UINT32 cbData
    )
{
    HRESULT hr = S_OK;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER dataSize = {0};
    DWORD bytesRead = 0;

    if((pbData == NULL) ||
       (cbData == 0))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    hFile = CreateFileW(
                    lpFileName,
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    0);
    if(hFile == INVALID_HANDLE_VALUE)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if(!GetFileSizeEx(hFile, &dataSize))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if((dataSize.HighPart != 0) ||
       (dataSize.LowPart < (offset + cbData)))
    {
        hr = NTE_BAD_DATA;
        goto Cleanup;
    }

    if(SetFilePointer(hFile, offset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    while(cbData > bytesRead)
    {
        DWORD bytesReadLast = 0;
        if(!ReadFile(hFile,
                        &pbData[bytesRead],
                        (DWORD)(cbData - bytesRead),
                        &bytesReadLast,
                        NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
        bytesRead += bytesReadLast;
    }

Cleanup:
    if(hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    return hr;
}

void
PcpToolCallResult(
    _In_ WCHAR* func,
    HRESULT hr
    )
{
    PWSTR Buffer = NULL;
    DWORD result = 0;

    if(FAILED(hr))
    {
        result = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                               FORMAT_MESSAGE_FROM_SYSTEM |
                               FORMAT_MESSAGE_IGNORE_INSERTS,
                               (PVOID)GetModuleHandle(NULL),
                               hr,
                               MAKELANGID(LANG_NEUTRAL,SUBLANG_NEUTRAL),
                              (PTSTR)&Buffer,
                               0,
                               NULL);

        if (result != 0)
        {
            wprintf(L"ERROR - %s: (0x%08lx) %s\n", func, hr, Buffer);
        }
        else
        {
            wprintf(L"ERROR - %s: (0x%08lx)\n", func, hr);
        }
        LocalFree(Buffer);
    }
}

