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
    wprintf_s(L"Tpmtool version 1.0\n\n");

    wprintf_s(L"Commands:\n");
    wprintf_s(L"\nGeneral:\n");
    wprintf_s(L" GetVersion\n");
	wprintf_s(L" GetTpmVersion\n");

    wprintf_s(L"\nRNG:\n");
    wprintf_s(L" GetRandom [size] {seed data} {output file}\n");

    wprintf_s(L"\nPersistent TPM Keys:\n");
    wprintf_s(L" GetEK {key file}\n");
    wprintf_s(L" GetEKCert {cert file}\n");
    wprintf_s(L" GetNVEKCert {cert file}\n");
    wprintf_s(L" AddEKCert [cert file]\n");
    wprintf_s(L" ExtractEK [cert file] {key file}\n");
    wprintf_s(L" GetSRK {key file}\n");
    wprintf_s(L" IssueEKCert [EKPub File] [Subject Name] {Cert file}\n");

    wprintf_s(L"\nPCPKey Management:\n");
    wprintf_s(L" EnumerateKeys\n");
    wprintf_s(L" GetCertStore\n");
    wprintf_s(L" CreateKey [key name] {usageAuth | @ | ! } {migrationAuth} {pcrMask} {pcrs}\n");
	wprintf_s(L" CreateSigningKey [key name] {usageAuth | @ | ! } {migrationAuth} {pcrMask} {pcrs}\n");
	wprintf_s(L" CreateBindingKey [key name] {usageAuth | @ | ! } {migrationAuth} {pcrMask} {pcrs}\n");
    wprintf_s(L" ImportKey [key file] [key name] {usageAuth | @ | ! } {migrationAuth}\n");
	wprintf_s(L" ImportKeybyOpaqueBlob [opaque blob] [key name] {usageAuth | @ | ! } {migrationAuth}\n");
    wprintf_s(L" ExportKey [key name] [migrationAuth] {key file}\n");
    wprintf_s(L" ChangeKeyUsageAuth [key name] [usageAuth] [newUsageAuth]\n");
    wprintf_s(L" DeleteKey [key name]\n");
    wprintf_s(L" GetPubKey [key name] {key File}\n");
    wprintf_s(L" Encrypt [pubkey file] [data] {blob file}\n");
    wprintf_s(L" Decrypt [key name] [blob file] {usageAuth}\n");
	wprintf_s(L" Sign [key name] [data file] {usageAuth} {signature file}\n");
	wprintf_s(L" Unbind [key name] [blob file] {usageAuth} {secret file}\n");

    wprintf_s(L"\nAIK Management:\n");
    wprintf_s(L" CreateAIK [key name] {idBinding file} {nonce} {usageAuth | @ | ! }\n");
	wprintf_s(L" ImportAIK [key file] [key name] {usageAuth | @ | ! } {migrationAuth}\n");
	wprintf_s(L" CollateIdentityRequest [key name] [nonce | privCA] {usageAuth | @ | ! }\n");
	wprintf_s(L" CollateIdentityRequest2 [key name] [nonce | privCA] {usageAuth | @ | ! }\n");
    wprintf_s(L" GetPubAIK [idBinding file] {key File}\n");
    wprintf_s(L" ChallengeAIK [idBinding file] [EKPub File] [secret] {Blob file} {nonce}\n");
    wprintf_s(L" ActivateAIK [key name] [Blob file]\n");
	wprintf_s(L" ActivateIdentity [key name] [Blob]\n");
    wprintf_s(L" PrivacyCAChallenge [idBinding file] [EKPub File] [Subject] {Blob file} {nonce}\n");
    wprintf_s(L" PrivacyCAActivate [key name] [Blob file] {cert file}\n");

    wprintf_s(L"\nPlatform Configuration:\n");
    wprintf_s(L" GetPlatformCounters\n");
    wprintf_s(L" GetPCRs {pcrs file}\n");
    wprintf_s(L" GetLog [export file]\n");
    wprintf_s(L" GetArchivedLog [OsBootCount : @] [OsResumeCount : @] {export file}\n");
    wprintf_s(L" DecodeLog [log file]\n");
    wprintf_s(L" RegisterAIK [key name]\n");
    wprintf_s(L" EnumerateAIK\n");

    wprintf_s(L"\nPlatform Attestation:\n");
    wprintf_s(L" GetPlatformAttestation [aik name] {attestation file} {nonce} {aikAuth}\n");
	wprintf_s(L" AikQuote [aik name] {attestation file} {nonce} {aikAuth}\n");
    wprintf_s(L" CreatePlatformAttestationFromLog [log file] {attestation file} {aik name}\n");
    wprintf_s(L" DisplayPlatformAttestationFile [attestation file]\n");
    wprintf_s(L" ValidatePlatformAttestation [attestation file] [aikpub file] {nonce}\n");

    wprintf_s(L"\nKey Attestation:\n");
    wprintf_s(L" GetKeyAttestation [key name] [aik name] {attest} {nonce} {keyAuth} {aikAuth}\n");
    wprintf_s(L" GetKeyAttestationFromKey [key name] {attest} {AIK name}\n");
    wprintf_s(L" ValidateKeyAttestation [attest] [aikpub file] {nonce} {pcrMask} {pcrs}\n");
    wprintf_s(L" GetKeyProperties [attest]\n");

    wprintf_s(L"\nVSC Attestation:\n");
    wprintf_s(L" GetVscKeyAttestationFromKey {attest} {AIK name}\n");

    wprintf_s(L"\nKey Hostage:\n");
    wprintf_s(L" WrapKey [cert Name] [storagePub file] {key file} {usageAuth} {pcrMask} {pcrs}\n");
    wprintf_s(L" ImportPlatformKey [key file] [key name] {cert file}\n");

	wprintf_s(L"\nNVRAM: (the commands below are implemented specially for Intel TA, therefore may not work for generic cases\n");
	wprintf_s(L" NVInfo {nvIndex in hex}\n");
	wprintf_s(L" NVDefine [index] [size in hexicimal] [nvramPassword] {permissions}\n"); //"tpm_nvdefine -i " + index + " -s 0x14 -x -t -aNvramPassword -otpmOwnerPass --permissions=AUTHWRITE"
	wprintf_s(L" NVRelease [index]\n");
	wprintf_s(L" NVWrite [nvIndex] [nvramPassword] [data in hex]\n");
	wprintf_s(L" NVRead [nvIndex] [size in hexicimal]\n");
	wprintf_s(L" PCRextend [pcrIndex] [newDigest]\n");

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
        } else if(!_wcsicmp(command, L"gettpmversion"))
		{
			hr = PcpToolGetTpmVersion(argc, argv);
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
		else if (!_wcsicmp(command, L"importaik"))
		{
			hr = PcpToolImportAIK(argc, argv);
		}
		else if (!_wcsicmp(command, L"collateidentityrequest"))
		{
			hr = PcpToolCollateIdentityRequest(argc, argv);
		}
		else if (!_wcsicmp(command, L"collateidentityrequest2"))
		{
			hr = PcpToolCollateIdentityRequest2(argc, argv);
		}
        else if(!_wcsicmp(command, L"createkey"))
        {
            hr = PcpToolCreateKey(argc, argv);
        }
		else if (!_wcsicmp(command, L"createsigningkey"))
		{
			hr = PcpToolCreateSigningKey(argc, argv);
		}
		else if (!_wcsicmp(command, L"createbindingkey"))
		{
			hr = PcpToolCreateBindingKey(argc, argv);
		}
        else if(!_wcsicmp(command, L"getcertstore"))
        {
            hr = PcpToolGetUserCertStore(argc, argv);
        }
        else if(!_wcsicmp(command, L"importkey"))
        {
            hr = PcpToolImportKey(argc, argv);
        }
		else if (!_wcsicmp(command, L"importkeybyopaque"))
		{
			hr = PcpToolImportKeybyOpaque(argc, argv);
		}
		else if (!_wcsicmp(command, L"exportkey"))
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
		else if (!_wcsicmp(command, L"getpvtkey"))
		{
			hr = PcpToolGetPvtKey(argc, argv);
		}
		else if (!_wcsicmp(command, L"getfullkey"))
		{
			hr = PcpToolGetFullKey(argc, argv);
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
		else if (!_wcsicmp(command, L"decrypt"))
        {
            hr = PcpToolDecrypt(argc, argv);
        }
		else if (!_wcsicmp(command, L"sign"))
		{
			hr = PcpToolSign(argc, argv);
		}
		else if (!_wcsicmp(command, L"unbind"))
		{
			hr = PcpToolUnbind(argc, argv);
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
		else if (!_wcsicmp(command, L"pcrextend"))
		{
			hr = PcpToolPCRExtend(argc, argv);
		}
        else
        {
            wprintf_s(L"Command not found.");
        }
    }

    TpmAttiReleaseHashProviders();
    return SUCCEEDED(hr) ? 0 : 1;
}

