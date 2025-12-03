#ifndef TLSClient_h__
#define TLSClient_h__

#include "../Communication/ComCarrier.h"
#include "../Nila_DNSClient.h"
#include "../Socket.h"

// mbedTLS
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

#ifndef ComCarrier_State_Handshaking
#define ComCarrier_State_Handshaking ComCarrier_State_Resolving
#endif


typedef enum
{
    TLSClient_State_Error        = -1,
    TLSClient_State_Initiated    = 0,
    TLSClient_State_Resolving    = 1,
    TLSClient_State_Handshaking  = 2,
    TLSClient_State_Connected    = 3,
    TLSClient_State_Disconnected = 4
} TLSClient_State;

typedef struct TLSClient
{
    wString        m_Host;
    UInt16         m_Port;
    TLSClient_State m_State;
    char           m_CABundlePath[256];

    // Use your Socket* just like TLSClient does
    Socket*        m_Socket;

    // mbedTLS objects
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context  entropy;
    mbedtls_x509_crt         ca;

    // internals
    Bool           m_rngSeeded;
    //Bool           m_sslSetup;
    Bool           m_caLoaded;
} TLSClient;

int TLSClient_Initialize(TLSClient* c, const char* host, UInt16 port);
int TLSClient_InitializePtr(const char* host, UInt16 port, TLSClient** out);

void TLSClient_SetCABundle(TLSClient* c, const char* path);

ComCarrier_State TLSClient_Connect(void* _vClient);

int TLSClient_Read(void* _vClient, UInt8* _Buffer, unsigned int _Length);
int TLSClient_Write(void* _vClient, const UInt8* _Buffer, unsigned int _Length);

ComCarrier_State TLSClient_Disconnect(void* _vClient);

void TLSClient_Dispose(TLSClient* c);
void TLSClient_DisposePtr(TLSClient** p);

static inline void TLSClient_Interface_Dispose(void* _Client)
{
	TLSClient_Dispose((TLSClient*)_Client);
}

static inline void TLSClient_Interface_DisposePtr(void** _ClientPtr)
{
	TLSClient_DisposePtr((TLSClient**)_ClientPtr);
}

#endif // TLSClient_h__
