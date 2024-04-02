#include <NetCon.h>

void ChangeNetStateOff()
{
    CoInitialize(NULL);

    INetConnectionManager* pNetManager;
    INetConnection* pNetConnection;
    IEnumNetConnection* pEnum;

    if (S_OK != CoCreateInstance(&CLSID_ConnectionManager, NULL, CLSCTX_SERVER, &IID_INetConnectionManager, (void**)&pNetManager))
    {
        return;
    }

    pNetManager->lpVtbl->EnumConnections(pNetManager, NCME_DEFAULT, &pEnum);
    pNetManager->lpVtbl->Release(pNetManager);

    if (NULL == pEnum)
    {
        return;
    }

    ULONG celtFetched;

    while (pEnum->lpVtbl->Next(pEnum, 1, &pNetConnection, &celtFetched) == S_OK)
    {
        NETCON_PROPERTIES* properties;
        pNetConnection->lpVtbl->GetProperties(pNetConnection, &properties);
        pNetConnection->lpVtbl->Disconnect(pNetConnection); //½ûÓÃÍø¿¨
    }

    CoUninitialize();
    return;
}

void ChangeNetStateOn()
{
    CoInitialize(NULL);

    INetConnectionManager* pNetManager;
    INetConnection* pNetConnection;
    IEnumNetConnection* pEnum;

    if (S_OK != CoCreateInstance(&CLSID_ConnectionManager, NULL, CLSCTX_SERVER, &IID_INetConnectionManager, (void**)&pNetManager))
    {
        return;
    }

    pNetManager->lpVtbl->EnumConnections(pNetManager, NCME_DEFAULT, &pEnum);
    pNetManager->lpVtbl->Release(pNetManager);

    if (NULL == pEnum)
    {
        return;
    }

    ULONG celtFetched;

    while (pEnum->lpVtbl->Next(pEnum, 1, &pNetConnection, &celtFetched) == S_OK)
    {
        NETCON_PROPERTIES* properties;
        pNetConnection->lpVtbl->GetProperties(pNetConnection, &properties);
        pNetConnection->lpVtbl->Connect(pNetConnection); //ÆôÓÃÍø¿¨
    }

    CoUninitialize();
    return;
}