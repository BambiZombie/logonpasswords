/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_oe.h"

LIST_ENTRY gDPAPI_Masterkeys = {&gDPAPI_Masterkeys, &gDPAPI_Masterkeys};
LIST_ENTRY gDPAPI_Credentials = {&gDPAPI_Credentials, &gDPAPI_Credentials};
LIST_ENTRY gDPAPI_Domainkeys = {&gDPAPI_Domainkeys, &gDPAPI_Domainkeys};
// to do CREDHIST_encrypted
// to do Masterkey_encrypted

PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY kuhl_m_dpapi_oe_masterkey_get(LPCGUID guid)
{
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) gDPAPI_Masterkeys.Flink; entry != (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) &gDPAPI_Masterkeys; entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) entry->navigator.Flink)
		if(RtlEqualGuid(guid, &entry->data.guid))
			return entry;
	return NULL;
}

BOOL kuhl_m_dpapi_oe_masterkey_add(LPCGUID guid, LPCVOID key, DWORD keyLen)
{
	BOOL status = FALSE;
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry;
	BYTE digest[SHA_DIGEST_LENGTH];

	if(guid && key && keyLen)
	{
		if(!kuhl_m_dpapi_oe_masterkey_get(guid))
		{
			if(entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) LocalAlloc(LPTR, sizeof(KUHL_M_DPAPI_OE_MASTERKEY_ENTRY)))
			{
				RtlCopyMemory(&entry->data.guid, guid, sizeof(GUID));
				if(keyLen == SHA_DIGEST_LENGTH)
				{
					RtlCopyMemory(entry->data.keyHash, key, SHA_DIGEST_LENGTH);
					status = TRUE;
				}
				else
				{
					kull_m_crypto_hash(CALG_SHA1, key, keyLen, digest, sizeof(digest));
					RtlCopyMemory(entry->data.keyHash, digest, sizeof(digest));
					if(entry->data.key = (BYTE *) LocalAlloc(LPTR, keyLen))
					{
						RtlCopyMemory(entry->data.key, key, keyLen);
						entry->data.keyLen = keyLen;
						status = TRUE;
					}
				}
				entry->navigator.Blink = gDPAPI_Masterkeys.Blink;
				entry->navigator.Flink = &gDPAPI_Masterkeys;
				((PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) gDPAPI_Masterkeys.Blink)->navigator.Flink = (PLIST_ENTRY) entry;
				gDPAPI_Masterkeys.Blink= (PLIST_ENTRY) entry;
				status = TRUE;
			}
		}
	}
	else PRINT_ERROR(L"No GUID or Key Hash?");
	return status;
}

void kuhl_m_dpapi_oe_masterkey_delete(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry)
{
	if(entry)
	{
		((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Blink)->navigator.Flink = entry->navigator.Flink;
		((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink)->navigator.Blink = entry->navigator.Blink;

		if(entry->data.key)
			LocalFree(entry->data.key);
		LocalFree(entry);
	}
}

void kuhl_m_dpapi_oe_masterkey_descr(PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry)
{
	if(entry)
	{
		kprintf(L"GUID:");
		kull_m_string_displayGUID(&entry->data.guid);
		kprintf(L";");
		
		kprintf(L"KeyHash:");
		kull_m_string_wprintf_hex(entry->data.keyHash, sizeof(entry->data.keyHash), 0);
		kprintf(L";Key:%savailable\n", entry->data.key ? L"": L"not ");
	}
}

void kuhl_m_dpapi_oe_masterkeys_delete()
{
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY tmp, entry;
	for(entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) gDPAPI_Masterkeys.Flink; entry != (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) &gDPAPI_Masterkeys; entry = tmp)
	{
		tmp = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) entry->navigator.Flink;
		kuhl_m_dpapi_oe_masterkey_delete(entry);
	}
}

void kuhl_m_dpapi_oe_masterkeys_descr()
{
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) gDPAPI_Masterkeys.Flink; entry != (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) &gDPAPI_Masterkeys; entry = (PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY) entry->navigator.Flink)
		kuhl_m_dpapi_oe_masterkey_descr(entry);
}

PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY kuhl_m_dpapi_oe_credential_get(LPCWSTR sid, LPCGUID guid)
{
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry;
	BOOL cmpGuid, cmpSid;
	for(entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) gDPAPI_Credentials.Flink; entry != (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) &gDPAPI_Credentials; entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink)
	{
		cmpSid = sid && (_wcsicmp(sid, entry->data.sid) == 0);
		cmpGuid = guid && (entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID) && RtlEqualGuid(guid, &entry->data.guid);
		
		if(sid && guid)
		{
			if(cmpSid && cmpGuid)
				return entry;
		}
		else if (sid)
		{
			if(cmpSid && !(entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID))
				return entry;
		}
		else if(guid)
		{
			if(cmpGuid)
				return entry;
		}
	}
	return NULL;
}

BOOL kuhl_m_dpapi_oe_credential_copyEntryWithNewGuid(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid)
{
	BOOL status = FALSE;
	if(entry && guid && !(entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID))
		status = kuhl_m_dpapi_oe_credential_add(entry->data.sid, guid, (entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4) ? entry->data.md4hash : NULL, (entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1) ? entry->data.sha1hash : NULL, (entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4p) ? entry->data.md4protectedhash : NULL, NULL);
	return status;
}


BOOL kuhl_m_dpapi_oe_credential_addtoEntry(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password)
{
	DWORD SidLen, PasswordLen;
	if(entry)
	{
		SidLen = (DWORD) wcslen(entry->data.sid) * sizeof(wchar_t);
		if(!(entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID) && guid)
		{
			RtlCopyMemory(&entry->data.guid, guid, sizeof(GUID));
			entry->data.flags |= KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID;
		}
		if(password)
			PasswordLen = (DWORD) wcslen(password) * sizeof(wchar_t);

		if(!(entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4) && (md4hash || password))
		{
			if(md4hash)
				RtlCopyMemory(entry->data.md4hash, md4hash, LM_NTLM_HASH_LENGTH);
			else
				kull_m_crypto_hash(CALG_MD4, password, PasswordLen, entry->data.md4hash, LM_NTLM_HASH_LENGTH);

			if(kull_m_crypto_hmac(CALG_SHA1, entry->data.md4hash, LM_NTLM_HASH_LENGTH, entry->data.sid, SidLen + sizeof(wchar_t), entry->data.md4hashDerived, SHA_DIGEST_LENGTH))
				entry->data.flags |= KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4;
		}
		if(!(entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1) && (sha1hash || password))
		{
			if(sha1hash)
				RtlCopyMemory(entry->data.sha1hash, sha1hash, SHA_DIGEST_LENGTH);
			else
				kull_m_crypto_hash(CALG_SHA1, password, PasswordLen, entry->data.sha1hash, SHA_DIGEST_LENGTH);

			kull_m_crypto_hmac(CALG_SHA1, entry->data.sha1hash, SHA_DIGEST_LENGTH, entry->data.sid, SidLen + sizeof(wchar_t), entry->data.sha1hashDerived, SHA_DIGEST_LENGTH);
			entry->data.flags |= KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1;
		}
		//if(!entry->md4protectedhash && (md4protectedhash || entry->md4hash))
		//{
		//		if(md4protectedhash)
		//			RtlCopyMemory(entry->md4protectedhash, md4protectedhash, LM_NTLM_HASH_LENGTH);
		//		else
		//			if(kull_m_crypto_pkcs5_pbkdf2_hmac(CALG_SHA_256, entry->md4hash, LM_NTLM_HASH_LENGTH, sid, SidLen, 10000, sha2, sizeof(sha2), FALSE))
		//				kull_m_crypto_pkcs5_pbkdf2_hmac(CALG_SHA_256, sha2, sizeof(sha2), sid, SidLen, 1, (PBYTE) entry->md4protectedhash, LM_NTLM_HASH_LENGTH, FALSE);
		//		kull_m_crypto_hmac(CALG_SHA1, entry->md4protectedhash, LM_NTLM_HASH_LENGTH, sid, SidLen + sizeof(wchar_t), entry->md4protectedhashDerived, SHA_DIGEST_LENGTH);
		//}
		//kuhl_m_dpapi_oe_credential_descr(entry);
	}
	return TRUE;
}

BOOL kuhl_m_dpapi_oe_credential_add(LPCWSTR sid, LPCGUID guid, LPCVOID md4hash, LPCVOID sha1hash, LPCVOID md4protectedhash, LPCWSTR password)
{
	BOOL status = FALSE;
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry;

	if(sid)
	{
		if(kuhl_m_dpapi_oe_is_sid_valid_ForCacheOrAuto(NULL, sid, FALSE))
		{
			if(!(entry = kuhl_m_dpapi_oe_credential_get(sid, guid)))
			{
				if(entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) LocalAlloc(LPTR, sizeof(KUHL_M_DPAPI_OE_CREDENTIAL_ENTRY)))
				{
					entry->data.sid = _wcsdup(sid);
					entry->navigator.Blink = gDPAPI_Credentials.Blink;
					entry->navigator.Flink = &gDPAPI_Credentials;
					((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) gDPAPI_Credentials.Blink)->navigator.Flink = (PLIST_ENTRY) entry;
					gDPAPI_Credentials.Blink= (PLIST_ENTRY) entry;
				}
			}
			if(entry)
				status = kuhl_m_dpapi_oe_credential_addtoEntry(entry, guid, md4hash, sha1hash, md4protectedhash, password);
		}
	}
	else PRINT_ERROR(L"No SID?");
	return status;
}

void kuhl_m_dpapi_oe_credential_delete(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry)
{
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entryB = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Blink, entryF = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink;
	
	if(entry)
	{
		((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Blink)->navigator.Flink = entry->navigator.Flink;
		((PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink)->navigator.Blink = entry->navigator.Blink;
		if(entry->data.sid)
			free(entry->data.sid);
		LocalFree(entry);
	}
}

void kuhl_m_dpapi_oe_credential_descr(PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry)
{
	if(entry)
	{
		if(entry->data.sid)
			kprintf(L"SID:%s", entry->data.sid);
		kprintf(L";");
		if(entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_GUID)
		{
			kprintf(L"GUID:");
			kull_m_string_displayGUID(&entry->data.guid);
		}
		kprintf(L";");
		if(entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4)
		{
			kprintf(L"MD4:");
			kull_m_string_wprintf_hex(entry->data.md4hash, LM_NTLM_HASH_LENGTH, 0);
		}
		kprintf(L";");
		if(entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_SHA1)
		{
			kprintf(L"SHA1:");
			kull_m_string_wprintf_hex(entry->data.sha1hash, SHA_DIGEST_LENGTH, 0);
		}
		kprintf(L";");
		if(entry->data.flags & KUHL_M_DPAPI_OE_CREDENTIAL_FLAG_MD4p)
		{
			kprintf(L"MD4p:");
			kull_m_string_wprintf_hex(entry->data.md4protectedhash, LM_NTLM_HASH_LENGTH, 0);
		}
		kprintf(L"\n");
	}
}

void kuhl_m_dpapi_oe_credentials_delete()
{
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY tmp, entry;
	for(entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) gDPAPI_Credentials.Flink; entry != (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) &gDPAPI_Credentials; entry = tmp)
	{
		tmp = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink;
		kuhl_m_dpapi_oe_credential_delete(entry);
	}
}

void kuhl_m_dpapi_oe_credentials_descr()
{
	PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) gDPAPI_Credentials.Flink; entry != (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) &gDPAPI_Credentials; entry = (PKUHL_M_DPAPI_OE_CREDENTIAL_ENTRY) entry->navigator.Flink)
		kuhl_m_dpapi_oe_credential_descr(entry);
}

PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY kuhl_m_dpapi_oe_domainkey_get(LPCGUID guid)
{
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Flink; entry != (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) &gDPAPI_Domainkeys; entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Flink)
		if(RtlEqualGuid(guid, &entry->data.guid))
			return entry;
	return NULL;
}

BOOL kuhl_m_dpapi_oe_domainkey_add(LPCGUID guid, LPCVOID key, DWORD keyLen, BOOL isNewKey)
{
	BOOL status = FALSE;
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry;
	if(guid && key && keyLen)
	{
		if(!kuhl_m_dpapi_oe_domainkey_get(guid))
		{
			if(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) LocalAlloc(LPTR, sizeof(KUHL_M_DPAPI_OE_DOMAINKEY_ENTRY)))
			{
				RtlCopyMemory(&entry->data.guid, guid, sizeof(GUID));
				entry->data.isNewKey = isNewKey;
				if(entry->data.key = (BYTE *) LocalAlloc(LPTR, keyLen))
				{
					RtlCopyMemory(entry->data.key, key, keyLen);
					entry->data.keyLen = keyLen;
					status = TRUE;
				}
				entry->navigator.Blink = gDPAPI_Domainkeys.Blink;
				entry->navigator.Flink = &gDPAPI_Domainkeys;
				((PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Blink)->navigator.Flink = (PLIST_ENTRY) entry;
				gDPAPI_Domainkeys.Blink= (PLIST_ENTRY) entry;
			}
		}
	}
	else PRINT_ERROR(L"No GUID or Key?");
	return status;
}

void kuhl_m_dpapi_oe_domainkey_delete(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry)
{
	if(entry)
	{
		((PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Blink)->navigator.Flink = entry->navigator.Flink;
		((PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Flink)->navigator.Blink = entry->navigator.Blink;

		if(entry->data.key)
			LocalFree(entry->data.key);
		LocalFree(entry);
	}
}

void kuhl_m_dpapi_oe_domainkey_descr(PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry)
{
	if(entry)
	{
		kprintf(L"GUID:");
		kull_m_string_displayGUID(&entry->data.guid);
		kprintf(L";TYPE:%s\n", entry->data.isNewKey ? L"RSA" : L"LEGACY");
	}
}

void kuhl_m_dpapi_oe_domainkeys_delete()
{
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY tmp, entry;
	for(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Flink; entry != (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) &gDPAPI_Domainkeys; entry = tmp)
	{
		tmp = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Flink;
		kuhl_m_dpapi_oe_domainkey_delete(entry);
	}
}

void kuhl_m_dpapi_oe_domainkeys_descr()
{
	PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY entry;
	for(entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) gDPAPI_Domainkeys.Flink; entry != (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) &gDPAPI_Domainkeys; entry = (PKUHL_M_DPAPI_OE_DOMAINKEY_ENTRY) entry->navigator.Flink)
		kuhl_m_dpapi_oe_domainkey_descr(entry);
}

NTSTATUS kuhl_m_dpapi_oe_clean()
{
	kuhl_m_dpapi_oe_credentials_delete();
	kuhl_m_dpapi_oe_masterkeys_delete();
	kuhl_m_dpapi_oe_domainkeys_delete();
	return STATUS_SUCCESS;
}

const DWORD invalidAuthorityForAuto[] = {18, 19, 20};
const DWORD invalidAuthorityForCache[] = {18, 19, 20, 80, 82, 83, 90, 96};
BOOL kuhl_m_dpapi_oe_is_sid_valid_ForCacheOrAuto(PSID sid, LPCWSTR szSid, BOOL AutoOrCache)
{
	BOOL status = FALSE;
	PUCHAR count;
	PSID tmpSid = NULL;
	DWORD s0, i, maxAuth;
	const DWORD *pAuth;

	if(szSid)
		ConvertStringSidToSid(szSid, &tmpSid);
	else tmpSid = sid;
	
	if(AutoOrCache)
	{
		pAuth = invalidAuthorityForAuto;
		maxAuth = ARRAYSIZE(invalidAuthorityForAuto);
	}
	else
	{
		pAuth = invalidAuthorityForCache;
		maxAuth = ARRAYSIZE(invalidAuthorityForCache);
	}

	if(IsValidSid(tmpSid))
	{
		if(count = GetSidSubAuthorityCount(tmpSid))
		{
			if(*count >= 1)
			{
				s0 = *GetSidSubAuthority(tmpSid, 0);
				status = TRUE;
				for(i = 0; i < maxAuth; i++)
				{
					if(pAuth[i] == s0)
					{
						status = FALSE;
						break;
					}
				}
			}
		}
	}
	return status;
}

BOOL kuhl_m_dpapi_oe_autosid(LPCWSTR filename, LPWSTR * pSid)
{
	BOOL status = FALSE;
	wchar_t *duplicate, *pE;
	PSID tmpSid;
	if(filename && (duplicate = _wcsdup(filename)))
	{
		if(pE = wcsrchr(duplicate, L'\\'))
		{
			*pE = L'\0';
			if(pE = wcsrchr(duplicate, L'\\'))
			{
				if(ConvertStringSidToSid(++pE, &tmpSid))
				{
					if(kuhl_m_dpapi_oe_is_sid_valid_ForCacheOrAuto(tmpSid, NULL, TRUE))
					{
						if(status = ConvertSidToStringSid(tmpSid, pSid))
							kprintf(L"Auto SID from path seems to be: %s\n", *pSid);
					}
					else kprintf(L"SID detected in path but not relevant, can be forced with /sid:S-1-...\n");
					LocalFree(tmpSid);
				}
			}
		}
		free(duplicate);
	}
	return status;
}
