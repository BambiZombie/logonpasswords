/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#pragma once
#include "../kuhl_m.h"
#include "../modules/kull_m_crypto_system.h"
#include "kuhl_m_kerberos_ticket.h"

#define KRB_KEY_USAGE_AS_REP_TGS_REP	2

typedef struct _KUHL_M_KERBEROS_LIFETIME_DATA {
	FILETIME TicketStart;
	FILETIME TicketEnd;
	FILETIME TicketRenew;
} KUHL_M_KERBEROS_LIFETIME_DATA, *PKUHL_M_KERBEROS_LIFETIME_DATA;

const KUHL_M kuhl_m_kerberos;

NTSTATUS kuhl_m_kerberos_init();
NTSTATUS kuhl_m_kerberos_clean();

NTSTATUS LsaCallKerberosPackage(PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength, PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength, PNTSTATUS ProtocolStatus);