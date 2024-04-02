/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi.h"

void kuhl_m_dpapi_display_MasterkeyInfosAndFree(LPCGUID guid, PVOID data, DWORD dataLen, PSID sid)
{
	BYTE digest[SHA_DIGEST_LENGTH];
	
	kprintf(L"  key : ");
	kull_m_string_wprintf_hex(data, dataLen, 0);
	kprintf(L"\n");
	if(guid)
		kuhl_m_dpapi_oe_masterkey_add(guid, data, dataLen);
	if(kull_m_crypto_hash(CALG_SHA1, data, dataLen, digest, sizeof(digest)))
	{
		kprintf(L"  sha1: ");
		kull_m_string_wprintf_hex(digest, sizeof(digest), 0);
		kprintf(L"\n");
	}
	LocalFree(data);
	if(sid)
	{
		kprintf(L"  sid : ");
		kull_m_string_displaySID(sid);
		kprintf(L"\n");
		LocalFree(sid);
	}
}

void kuhl_m_dpapi_display_CredHist(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID ntlm, LPCVOID sha1)
{
	PWSTR currentStringSid;
	kprintf(L"   "); kull_m_string_displaySID(entry->pSid); kprintf(L" -- "); kull_m_string_displayGUID(&entry->header.guid); kprintf(L"\n");
	kprintf(L"   > NTLM: "); kull_m_string_wprintf_hex(ntlm, LM_NTLM_HASH_LENGTH, 0); kprintf(L"\n");
	kprintf(L"   > SHA1: "); kull_m_string_wprintf_hex(sha1, SHA_DIGEST_LENGTH, 0); kprintf(L"\n");
	if(ConvertSidToStringSid(entry->pSid, &currentStringSid))
	{
		kuhl_m_dpapi_oe_credential_add(currentStringSid, &entry->header.guid, ntlm, sha1, NULL, NULL);
		LocalFree(currentStringSid);
	}
}