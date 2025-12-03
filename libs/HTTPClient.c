#include "HTTPClient.h"

void HTTPClient_Work(void* _Context, uint64_t _MonTime)
{
	
}

int HTTPClient_Initiate(HTTPClient* _Client)
{
	memset(_Client, 0, sizeof(HTTPClient));
	
	_Client->buffer = NULL;
	_Client->task = NULL;

	return 0;
}

int HTTPClient_GET(HTTPClient* _Client, const char* _URL, void (*callback)(HTTPClient* _CLient, const char* _Event))
{
	_Client->buffer = malloc(4096);
	if(_Client->buffer == NULL)
		return -1;


	snprintf(_Client->buffer, 4096, "GET %s HTTP/1.1\r\nHost: chas.se\r\nConnection: close\r\n\r\n", _URL);

	_Client->bufferPtr = _Client->buffer;

	_Client->task = smw_createTask(_Client, HTTPClient_Work);

}

void HTTPClient_Dispose(HTTPClient* _Client)
{
	if(_Client->task != NULL)
		smw_destroyTask(_Client->task);

	if(_Client->buffer != NULL)
		free(_Client->buffer);

}

