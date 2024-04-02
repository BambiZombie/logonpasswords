/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "../kuhl_m.h"
#include "../modules/kull_m_dpapi.h"

#include "kuhl_m_dpapi_oe.h"

const KUHL_M kuhl_m_dpapi;

void kuhl_m_dpapi_display_MasterkeyInfosAndFree(LPCGUID guid, PVOID data, DWORD dataLen, PSID sid);
void kuhl_m_dpapi_display_CredHist(PKULL_M_DPAPI_CREDHIST_ENTRY entry, LPCVOID ntlm, LPCVOID sha1);