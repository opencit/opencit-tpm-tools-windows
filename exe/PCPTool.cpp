/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    PCPTool.cpp

Author:

    Stefan Thom, stefanth@Microsoft.com, 2011/06/09

Abstract:

    Entrypoint and help screen for PCPTool.

--*/

#include "stdafx.h"

void
PcpToolGetHelp(
    )
{
    wprintf(L"Microsoft PCPTool version 1.0 for Windows 8\nPlatform Integrity - TPM Attestation Reference Implementation.\nStefan Thom, stefanth@microsoft.com, 2011-2012\nCopyright (c) Microsoft Corporation.  All rights reserved.\n\n");

    wprintf(L"Commands:\n");
    wprintf(L"\nGeneral:\n");
    wprintf(L" GetVersion\n");

    wprintf(L"\nRNG:\n");
    wprintf(L" GetRandom [size] {seed data} {output file}\n");

    wprintf(L"\nPersistent TPM Keys:\n");
    wprintf(L" GetEK {key file}\n");
    wprintf(L" GetEKCert {cert file}\n");
    wprintf(L" GetNVEKCert {cert file}\n");
    wprintf(L" AddEKCert [cert file]\n");
    wprintf(L" ExtractEK [cert file] {key file}\n");
    wprintf(L" GetSRK {key file}\n");
    wprintf(L" IssueEKCert [EKPub File] [Subject Name] {Cert file}\n");

    wprintf(L"\nPCPKey Management:\n");
    wprintf(L" EnumerateKeys\n");
    wprintf(L" GetCertStore\n");
    wprintf(L" CreateKey [key name] {usageAuth | @ | ! } {migrationAuth} {pcrMask} {pcrs}\n");
    wprintf(L" ImportKey [key file] [key name] {usageAuth | @ | ! } {migrationAuth}\n");
    wprintf(L" ExportKey [key name] [migrationAuth] {key file}\n");
    wprintf(L" ChangeKeyUsageAuth [key name] [usageAuth] [newUsageAuth]\n");
    wprintf(L" DeleteKey [key name]\n");
    wprintf(L" GetPubKey [key name] {key File}\n");
    wprintf(L" Encrypt [pubkey file] [data] {blob file}\n");
    wprintf(L" Decrypt [key name] [blob file] {usageAuth}\n");

    wprintf(L"\nAIK Management:\n");
    wprintf(L" CreateAIK [key name] {idBinding file} {nonce} {usageAuth | @ | ! }\n");
	wprintf(L" CollateIdentityRequest [key name] [nonce | privCA] {usageAuth | @ | ! }\n");
    wprintf(L" GetPubAIK [idBinding file] {key File}\n");
    wprintf(L" ChallengeAIK [idBinding file] [EKPub File] [secret] {Blob file} {nonce}\n");
    wprintf(L" ActivateAIK [key name] [Blob file]\n");
	wprintf(L" ActivateIdentity [key name] [Blob]\n");
    wprintf(L" PrivacyCAChallenge [idBinding file] [EKPub File] [Subject] {Blob file} {nonce}\n");
    wprintf(L" PrivacyCAActivate [key name] [Blob file] {cert file}\n");

    wprintf(L"\nPlatform Configuration:\n");
    wprintf(L" GetPlatformCounters\n");
    wprintf(L" GetPCRs {pcrs file}\n");
    wprintf(L" GetLog [export file]\n");
    wprintf(L" GetArchivedLog [OsBootCount : @] [OsResumeCount : @] {export file}\n");
    wprintf(L" DecodeLog [log file]\n");
    wprintf(L" RegisterAIK [key name]\n");
    wprintf(L" EnumerateAIK\n");

    wprintf(L"\nPlatform Attestation:\n");
    wprintf(L" GetPlatformAttestation [aik name] {attestation file} {nonce} {aikAuth}\n");
	wprintf(L" AikQuote [aik name] {attestation file} {nonce} {aikAuth}\n");
    wprintf(L" CreatePlatformAttestationFromLog [log file] {attestation file} {aik name}\n");
    wprintf(L" DisplayPlatformAttestationFile [attestation file]\n");
    wprintf(L" ValidatePlatformAttestation [attestation file] [aikpub file] {nonce}\n");

    wprintf(L"\nKey Attestation:\n");
    wprintf(L" GetKeyAttestation [key name] [aik name] {attest} {nonce} {keyAuth} {aikAuth}\n");
    wprintf(L" GetKeyAttestationFromKey [key name] {attest} {AIK name}\n");
    wprintf(L" ValidateKeyAttestation [attest] [aikpub file] {nonce} {pcrMask} {pcrs}\n");
    wprintf(L" GetKeyProperties [attest]\n");

    wprintf(L"\nVSC Attestation:\n");
    wprintf(L" GetVscKeyAttestationFromKey {attest} {AIK name}\n");

    wprintf(L"\nKey Hostage:\n");
    wprintf(L" WrapKey [cert Name] [storagePub file] {key file} {usageAuth} {pcrMask} {pcrs}\n");
    wprintf(L" ImportPlatformKey [key file] [key name] {cert file}\n");

	wprintf(L"\nNVRAM: (the commands below are implemented specially for Intel TA, therefore may not work for generic cases\n");
	wprintf(L" NVInfo {nvIndex in hex}\n");
	wprintf(L" NVDefine [index] [size] [nvramPassword] {permissions}\n"); //"tpm_nvdefine -i " + index + " -s 0x14 -x -t -aNvramPassword -otpmOwnerPass --permissions=AUTHWRITE"
	wprintf(L" NVRelease [index]\n");
	wprintf(L" NVWrite [nvIndex] [nvramPassword] [data in hex]\n");
	wprintf(L" NVRead [nvIndex]\n");

}

int __cdecl wmain(_In_ int argc,
           _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;

    if((argc <= 1) ||
       (!wcscmp(argv[1], L"/?")) ||
       (!wcscmp(argv[1], L"-?")) ||
       (!_wcsicmp(argv[1], L"/h")) ||
       (!_wcsicmp(argv[1], L"-h")))
    {
        PcpToolGetHelp();
    }
    else
    {
        WCHAR* command = argv[1];
        if(!_wcsicmp(command, L"getversion"))
        {
            hr = PcpToolGetVersion(argc, argv);
        }
        else if(!_wcsicmp(command, L"getrandom"))
        {
            hr = PcpToolGetRandom(argc, argv);
        }
        else if(!_wcsicmp(command, L"geteK"))
        {
            hr = PcpToolGetEK(argc, argv);
        }
        else if(!_wcsicmp(command, L"getekcert"))
        {
            hr = PcpToolGetEKCert(argc, argv);
        }
        else if(!_wcsicmp(command, L"getnvekcert"))
        {
            hr = PcpToolGetNVEKCert(argc, argv);
        }
        else if(!_wcsicmp(command, L"addekcert"))
        {
            hr = PcpToolAddEKCert(argc, argv);
        }
        else if(!_wcsicmp(command, L"extractek"))
        {
            hr = PcpToolExtractEK(argc, argv);
        }
        else if(!_wcsicmp(command, L"getsrk"))
        {
            hr = PcpToolGetSRK(argc, argv);
        }
        else if(!_wcsicmp(command, L"getlog"))
        {
            hr = PcpToolGetLog(argc, argv);
        }
        else if(!_wcsicmp(command, L"decodelog"))
        {
            hr = PcpToolDecodeLog(argc, argv);
        }
        else if(!_wcsicmp(command, L"createaik"))
        {
            hr = PcpToolCreateAIK(argc, argv);
        }
		else if (!_wcsicmp(command, L"collateidentityrequest"))
		{
			hr = PcpToolCollateIdentityRequest(argc, argv);
		}
        else if(!_wcsicmp(command, L"createkey"))
        {
            hr = PcpToolCreateKey(argc, argv);
        }
        else if(!_wcsicmp(command, L"getcertstore"))
        {
            hr = PcpToolGetUserCertStore(argc, argv);
        }
        else if(!_wcsicmp(command, L"importkey"))
        {
            hr = PcpToolImportKey(argc, argv);
        }
        else if(!_wcsicmp(command, L"exportkey"))
        {
            hr = PcpToolExportKey(argc, argv);
        }
        else if(!_wcsicmp(command, L"challengeaik"))
        {
            hr = PcpToolChallengeAIK(argc, argv);
        }
        else if(!_wcsicmp(command, L"activateaik"))
        {
            hr = PcpToolActivateAIK(argc, argv);
        }
		else if (!_wcsicmp(command, L"activateidentity"))
		{
			hr = PcpToolActivateIdentity(argc, argv);
		}
        else if(!_wcsicmp(command, L"getpubaik"))
        {
            hr = PcpToolGetPubAIK(argc, argv);
        }
        else if(!_wcsicmp(command, L"registeraik"))
        {
            hr = PcpToolRegisterAIK(argc, argv);
        }
        else if(!_wcsicmp(command, L"enumerateaik"))
        {
            hr = PcpToolEnumerateAIK(argc, argv);
        }
        else if(!_wcsicmp(command, L"enumeratekeys"))
        {
            hr = PcpToolEnumerateKeys(argc, argv);
        }
        else if(!_wcsicmp(command, L"changekeyusageauth"))
        {
            hr = PcpToolChangeKeyUsageAuth(argc, argv);
        }
        else if(!_wcsicmp(command, L"deletekey"))
        {
            hr = PcpToolDeleteKey(argc, argv);
        }
        else if(!_wcsicmp(command, L"getpubkey"))
        {
            hr = PcpToolGetPubKey(argc, argv);
        }
        else if(!_wcsicmp(command, L"getplatformcounters"))
        {
            hr = PcpToolGetPlatformCounters(argc, argv);
        }
        else if(!_wcsicmp(command, L"getpcrs"))
        {
            hr = PcpToolGetPCRs(argc, argv);
        }
        else if(!_wcsicmp(command, L"getarchivedlog"))
        {
            hr = PcpToolGetArchivedLog(argc, argv);
        }
        else if(!_wcsicmp(command, L"getplatformattestation"))
        {
            hr = PcpToolGetPlatformAttestation(argc, argv);
        }
		else if (!_wcsicmp(command, L"aikquote"))
		{
			hr = PcpToolAikQuote(argc, argv);
		}
        else if(!_wcsicmp(command, L"createplatformattestationfromlog"))
        {
            hr = PcpToolCreatePlatformAttestationFromLog(argc, argv);
        }
        else if(!_wcsicmp(command, L"displayplatformattestationfile"))
        {
            hr = PcpToolDisplayPlatformAttestationFile(argc, argv);
        }
        else if(!_wcsicmp(command, L"validateplatformattestation"))
        {
            hr = PcpToolValidatePlatformAttestation(argc, argv);
        }
        else if(!_wcsicmp(command, L"getkeyattestation"))
        {
            hr = PcpToolGetKeyAttestation(argc, argv);
        }
        else if(!_wcsicmp(command, L"getkeyattestationfromkey"))
        {
            hr = PcpToolGetKeyAttestationFromKey(argc, argv);
        }
        else if(!_wcsicmp(command, L"validatekeyattestation"))
        {
            hr = PcpToolValidateKeyAttestation(argc, argv);
        }
        else if(!_wcsicmp(command, L"getkeyproperties"))
        {
            hr = PcpToolGetKeyProperties(argc, argv);
        }
        else if(!_wcsicmp(command, L"encrypt"))
        {
            hr = PcpToolEncrypt(argc, argv);
        }
        else if(!_wcsicmp(command, L"decrypt"))
        {
            hr = PcpToolDecrypt(argc, argv);
        }
        else if(!_wcsicmp(command, L"wrapkey"))
        {
            hr = PcpToolWrapPlatformKey(argc, argv);
        }
        else if(!_wcsicmp(command, L"importplatformkey"))
        {
            hr = PcpToolImportPlatformKey(argc, argv);
        }
        else if(!_wcsicmp(command, L"getvsckeyattestationfromkey"))
        {
            hr = PcpToolGetVscKeyAttestationFromKey(argc, argv);
        }
        else if(!_wcsicmp(command, L"issueekcert"))
        {
            hr = PcpToolIssueEkCert(argc, argv);
        }
        else if(!_wcsicmp(command, L"privacycachallenge"))
        {
            hr = PcpToolPrivacyCaChallenge(argc, argv);
        }
        else if(!_wcsicmp(command, L"nvinfo"))
        {
            hr = PcpToolNVInfo(argc, argv);
        }
		else if (!_wcsicmp(command, L"nvread"))
		{
			hr = PcpToolNVRead(argc, argv);
		}
		else if (!_wcsicmp(command, L"nvwrite"))
		{
			hr = PcpToolNVWrite(argc, argv);
		}
		else if (!_wcsicmp(command, L"nvdefine"))
		{
			hr = PcpToolNVDefine(argc, argv);
		}
		else if (!_wcsicmp(command, L"nvrelease"))
		{
			hr = PcpToolNVRelease(argc, argv);
		}
        else
        {
            wprintf(L"Command not found.");
        }
    }

    TpmAttiReleaseHashProviders();
    return SUCCEEDED(hr) ? 0 : 1;
}

