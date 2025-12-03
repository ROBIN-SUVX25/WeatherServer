#include "TLSClient.h"
#include <string.h>

static int tlsclient_tcp_connected(Socket* s)
{
#if defined(_WIN32)
    char err = 0; int len = sizeof(err);
    if (getsockopt(s->m_FD, SOL_SOCKET, SO_ERROR, &err, &len) < 0) return 0;
    return err == 0;
#else
    int err = 0; socklen_t len = sizeof(err);
    if (getsockopt(s->m_FD, SOL_SOCKET, SO_ERROR, &err, &len) < 0) return 0;
    return err == 0;
#endif
}

static int tlsclient_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    Socket *s = (Socket*)ctx;
    int r = Socket_Write(s, buf, (unsigned)len);
    if (r == 0)  return MBEDTLS_ERR_SSL_WANT_WRITE;

    if (r < 0) {
        // If TCP not connected yet, ask mbedTLS to try again later
        if (!tlsclient_tcp_connected(s)) return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    return r;
}

static int tlsclient_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    Socket *s = (Socket*)ctx;
    int r = Socket_Read(s, buf, (unsigned)len);
    if (r == 0)  return MBEDTLS_ERR_SSL_WANT_READ;

    if (r < 0) {
        if (!tlsclient_tcp_connected(s)) return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    return r;
}

int TLSClient_Initialize(TLSClient* c, const char* host, UInt16 port)
{
    // Init string
    if (wString_Initialize(&c->m_Host, 8) != 0)
        return -1;

    if (host)
        wString_Set(&c->m_Host, host);

    c->m_Port      = port;
    c->m_State     = TLSClient_State_Initiated;

    c->m_CABundlePath[0] = '\0';

    // Match TCPClient: socket is a pointer we create later via Socket_InitializePtr
    c->m_Socket = NULL;

    // mbedTLS objects
    mbedtls_ssl_init(&c->ssl);
    mbedtls_ssl_config_init(&c->conf);
    mbedtls_ctr_drbg_init(&c->ctr_drbg);
    mbedtls_entropy_init(&c->entropy);
    mbedtls_x509_crt_init(&c->ca);

    // internal flags
    c->m_rngSeeded = False;
    c->m_caLoaded  = False;

    return 0;
}

int TLSClient_InitializePtr(const char* host, UInt16 port, TLSClient** out)
{
    TLSClient* c = (TLSClient*)WAllocator_Alloc(sizeof(TLSClient));
    if (!c)
		return -1;

    memset(c, 0, sizeof(*c));
    if (TLSClient_Initialize(c, host, port) != 0)
	{
		WAllocator_Free(c);
		return -1;
	}

    *out = c;
    return 0;
}

void TLSClient_SetCABundle(TLSClient* c, const char* path)
{
    strncpy(c->m_CABundlePath, path, sizeof(c->m_CABundlePath) - 1);
    c->m_CABundlePath[sizeof(c->m_CABundlePath)-1] = '\0';
}

ComCarrier_State TLSClient_Connect(void* _vClient)
{
    TLSClient* c = (TLSClient*)_vClient;
	int result;

    if (c->m_State == TLSClient_State_Connected)
        return ComCarrier_State_Connected;

    // Seed RNG once
    if (!c->m_rngSeeded)
	{
        const char* pers = "tlsclient";
		result = mbedtls_ctr_drbg_seed(&c->ctr_drbg, mbedtls_entropy_func, &c->entropy, (const unsigned char*)pers, (size_t)strlen(pers));
        if (result != 0)
		{
			wrintf("TLSClient: mbedtls_ctr_drbg_seed failed: %d\n", result);
            c->m_State = TLSClient_State_Error;
			return ComCarrier_State_Error;
        }
        c->m_rngSeeded = True;
    }

    // Load CA bundle once
    if (!c->m_caLoaded)
	{
        if (c->m_CABundlePath[0] == '\0')
		{
			wrintf("TLSClient: CA bundle path not set.\n");
			c->m_State = TLSClient_State_Error;
			return ComCarrier_State_Error;
		}

		result = mbedtls_x509_crt_parse_file(&c->ca, c->m_CABundlePath); 
        if (result < 0)
		{
			wrintf("TLSClient: mbedtls_x509_crt_parse_file failed: %d\n", result);
            c->m_State = TLSClient_State_Error;
			return ComCarrier_State_Error;
        }

        c->m_caLoaded = True;
    }

    UInt32 remoteAddress = 0;
    Nila_DNSClient_Resolve_State state = Nila_DNSClient_Resolve(c->m_Host.str, &remoteAddress);
    if (state == Nila_DNSClient_Resolve_State_Requested)
	{
        c->m_State = TLSClient_State_Resolving;
        return ComCarrier_State_Again;
    }
    else if (state != Nila_DNSClient_Resolve_State_Resolved && state != Nila_DNSClient_Resolve_State_Stale)
	{
		wrintf("TLSClient: DNS resolve failed: %i\n", state);
        c->m_State = TLSClient_State_Error;
        return ComCarrier_State_Error;
    }

    if (c->m_Socket != NULL)
	{
        Socket_DisposePtr(&c->m_Socket);
	}
	
	result = Socket_InitializePtr(SOCK_STREAM, IPPROTO_TCP, remoteAddress, c->m_Port, NULL, &c->m_Socket);
    if (result != 0)
	{
		wrintf("TLSClient: Socket_InitializePtr failed: %d\n", result);
        c->m_State = TLSClient_State_Error;
        return ComCarrier_State_Error;
    }

	if (c->m_Socket && c->m_Socket->m_FD != SOCKET_INVALID)
	{
		if (!tlsclient_tcp_connected(c->m_Socket))
		{
			wrintf("TLSClient: Socket not connected, waiting for connection...\n");
			c->m_State = TLSClient_State_Resolving; // or a TCPConnecting state if you have one
			return ComCarrier_State_Again;           // keep calling Connect() until TCP is ready
		}
	}

	result = mbedtls_ssl_config_defaults(&c->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (result != 0)
	{
		wrintf("TLSClient: mbedtls_ssl_config_defaults failed: %d\n", result);
		c->m_State = TLSClient_State_Error;
		return ComCarrier_State_Error;
	}

	mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_rng(&c->conf, mbedtls_ctr_drbg_random, &c->ctr_drbg);
	mbedtls_ssl_conf_ca_chain(&c->conf, &c->ca, NULL);

	mbedtls_ssl_conf_min_tls_version(&c->conf, MBEDTLS_SSL_VERSION_TLS1_2);
	
	result = mbedtls_ssl_setup(&c->ssl, &c->conf);
	if (result != 0)
	{
		wrintf("TLSClient: mbedtls_ssl_setup failed: %d\n", result);
		c->m_State = TLSClient_State_Error;
		return ComCarrier_State_Error;
	}

	result = mbedtls_ssl_set_hostname(&c->ssl, c->m_Host.str);
	if (result != 0)
	{
		wrintf("TLSClient: mbedtls_ssl_set_hostname failed: %d\n", result);
		c->m_State = TLSClient_State_Error;
		return ComCarrier_State_Error;
	}

	mbedtls_ssl_set_bio(&c->ssl, c->m_Socket, tlsclient_bio_send, tlsclient_bio_recv, NULL);

	c->m_State = TLSClient_State_Connected;
	return ComCarrier_State_Connected;
}

int TLSClient_Read(void* _vClient, UInt8* _Buffer, unsigned int _Length)
{
    TLSClient* c = (TLSClient*)_vClient;
    int r = mbedtls_ssl_read(&c->ssl, _Buffer, _Length);

    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
		return 0;

    return r;
}

int TLSClient_Write(void* _vClient, const UInt8* _Buffer, unsigned int _Length)
{
    TLSClient* c = (TLSClient*)_vClient;
    int r = mbedtls_ssl_write(&c->ssl, _Buffer, _Length);

    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
		return 0;

    return r;
}

ComCarrier_State TLSClient_Disconnect(void* _vClient)
{
    TLSClient* c = (TLSClient*)_vClient;
    mbedtls_ssl_close_notify(&c->ssl);
	
	if(c->m_Socket != NULL)
		Socket_DisposePtr(&c->m_Socket);

    c->m_State = TLSClient_State_Disconnected;
    return ComCarrier_State_Disconnected;
}

void TLSClient_Dispose(TLSClient* c)
{
	TLSClient_Disconnect(c);

    mbedtls_x509_crt_free(&c->ca);
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->conf);
    mbedtls_ctr_drbg_free(&c->ctr_drbg);
    mbedtls_entropy_free(&c->entropy);

    wString_Dispose(&c->m_Host);
    memset(c, 0, sizeof(*c));
}

void TLSClient_DisposePtr(TLSClient** p)
{
    if (!p || !*p)
		return;

    TLSClient_Dispose(*p);
    WAllocator_Free(*p);
    *(p) = NULL;
}
