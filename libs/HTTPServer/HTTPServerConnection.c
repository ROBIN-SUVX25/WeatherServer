#include "HTTPServerConnection.h"
#include "utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

//-----------------Internal Functions-----------------

void HTTPServerConnection_TaskWork(void* _Context, uint64_t _MonTime);
void HTTPServerConnection_SetMethodURL(HTTPServerConnection* _Connection, const char* _Method, const char* _URL);

//----------------------------------------------------

int HTTPServerConnection_Initiate(HTTPServerConnection* _Connection, int _FD)
{
	TCPClient_Initiate(&_Connection->tcpClient, _FD);
	
	_Connection->task = smw_createTask(_Connection, HTTPServerConnection_TaskWork);

	return 0;
}

int HTTPServerConnection_InitiatePtr(int _FD, HTTPServerConnection** _ConnectionPtr)
{
	if(_ConnectionPtr == NULL)
		return -1;

	HTTPServerConnection* _Connection = (HTTPServerConnection*)malloc(sizeof(HTTPServerConnection));
	if(_Connection == NULL)
		return -2;

	int result = HTTPServerConnection_Initiate(_Connection, _FD);
	if(result != 0)
	{
		free(_Connection);
		return result;
	}

	*(_ConnectionPtr) = _Connection;

	return 0;
}

void HTTPServerConnection_SetCallback(HTTPServerConnection* _Connection, void* _Context, HTTPServerConnection_OnRequest _OnRequest)
{
	_Connection->context = _Context;
	_Connection->onRequest = _OnRequest;
}

void HTTPServerConnection_TaskWork(void* _Context, uint64_t _MonTime)
{
	HTTPServerConnection* _Connection = (HTTPServerConnection*)_Context;
	size_t capacity = 512;
  	int bytesRecieved;
  	size_t usedSpace = 0;
  	char *response = (char *)malloc(capacity + 1);
  	if (response == NULL) {
    	perror("malloc");
    	return;
  	}

  	uint64_t now = SystemMonotonicMS();
  	uint64_t timeout = now + 5000;

  	while (now < timeout) {
    	now = SystemMonotonicMS();

    	if (usedSpace >= capacity) {
      		size_t newCapacity = capacity * 2;
      		char *tempBuf = (char *)realloc(response, newCapacity + 1);
      	if (!tempBuf) {
        	free(response);
        	perror("realloc");
        	return;
      	}
      	capacity = newCapacity;
      	response = tempBuf;
    	}

    	size_t spaceLeft = capacity - usedSpace;

    	bytesRecieved = TCPClient_Read(&_Connection->tcpClient, (uint8_t *)response + usedSpace, spaceLeft);

    	if (bytesRecieved > 0) {
      		usedSpace += bytesRecieved;
      		continue;
    	} else if (bytesRecieved == 0) {
      		break;
    	}
  	}

  	if (bytesRecieved > 0) {
    	printf("TIMEOUT ON READ!\r\n");
    	return;
  	}

	response[usedSpace] = '\0';
	
	char method[16];
	char URL[256];

	sscanf(response, "%15s%*[^\n]\nHost: %255s[^\n]\n", method, URL);

	if (strcmp(method, "GET") == 0) {
		HTTPServerConnection_SetMethodURL(_Connection->context, method, URL);
		_Connection->onRequest(_Connection->context);
	}
}

void HTTPServerConnection_SetMethodURL(HTTPServerConnection* _Connection, const char* _Method, const char* _URL) {
	if (!_Connection || !_Method || !_URL)
	{
		return;
	}

	_Connection->method = utils_strdup(_Method);
	_Connection->url = utils_strdup(_URL);
	
	return;
}

void HTTPServerConnection_Dispose(HTTPServerConnection* _Connection)
{
	TCPClient_Dispose(&_Connection->tcpClient);
	smw_destroyTask(_Connection->task);
}

void HTTPServerConnection_DisposePtr(HTTPServerConnection** _ConnectionPtr)
{
	if(_ConnectionPtr == NULL || *(_ConnectionPtr) == NULL)
		return;

	HTTPServerConnection_Dispose(*(_ConnectionPtr));
	free(*(_ConnectionPtr));
	*(_ConnectionPtr) = NULL;
}
