
#ifndef __HTTPServerConnection_h_
#define __HTTPServerConnection_h_

#include "smw.h"
#include "../TCPClient.h"

typedef int (*HTTPServerConnection_OnRequest)(void* _Context);

typedef enum
{
	HTTPServerConnection_State_Init,
	HTTPServerConnection_State_Reading,
	HTTPServerConnection_State_Parsing,
	HTTPServerConnection_State_Timeout,
	HTTPServerConnection_State_Done,
	HTTPServerConnection_State_Dispose,
	HTTPServerConnection_State_Failed
} HTTPServerConnection_State;

#define READBUFFER_SIZE 4096
#define HTTPSERVER_TIMEOUT_MS 1000

typedef struct
{
	TCPClient tcpClient;
	char readBuffer[READBUFFER_SIZE];
	int bytesRead;
	uint64_t startTime;

	void* context;
	HTTPServerConnection_OnRequest onRequest;

	char* method;
	char* url;

	smw_task* task;
	HTTPServerConnection_State state;
} HTTPServerConnection;


int HTTPServerConnection_Initiate(HTTPServerConnection* _Connection, int _FD);
int HTTPServerConnection_InitiatePtr(int _FD, HTTPServerConnection** _ConnectionPtr);

void HTTPServerConnection_SetCallback(HTTPServerConnection* _Connection, void* _Context, HTTPServerConnection_OnRequest _OnRequest);

void HTTPServerConnection_Dispose(HTTPServerConnection* _Connection);
void HTTPServerConnection_DisposePtr(HTTPServerConnection** _ConnectionPtr);

#endif //__HTTPServerConnection_h_
