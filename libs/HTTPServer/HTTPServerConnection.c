#include "HTTPServerConnection.h"
#include "../TCPClient.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>




//-----------------Internal Functions-----------------


void HTTPServerConnection_TaskWork(void* _Context, uint64_t _MonTime);

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
	uint8_t buffer[1024];
	memset(&buffer[0], 0, sizeof(buffer));
	HTTPServerConnection* _Connection = (HTTPServerConnection*)_Context;
	HTTPRequest _Request = {0};
	
	int totalBytesRead = 0;

	while(1)
	{
		int bytesRead = TCPClient_Read(&_Connection->tcpClient, &buffer[totalBytesRead], sizeof(buffer));

		if(bytesRead < 0)
		{
			break;
		}	

		if(bytesRead == 0)
		{
			break;
		}
		
		totalBytesRead += bytesRead;
	}
	
	if(totalBytesRead > 0)
	{		
		char* lines = strtok((char*)buffer, " ");
		_Connection->method = strdup(lines);
		lines = strtok(NULL, "\r\n");

		int y = 0;
		while(lines != NULL)
		{
			sscanf(lines, "%255[^:]: %255[^\r\n]", _Request.headers[y].key, _Request.headers[y].value);			

			if(strcmp(_Request.headers[y].key, "Host") == 0)
			{
				_Connection->url = strdup(_Request.headers[y].value);
			}

			lines = strtok(NULL, "\r\n");
			y++;
		}
		
		if(strcmp(_Connection->method, "GET") == 0)
		{
			_Request._URL = _Connection->url;
			_Request._Method = _Connection->method;
			_Connection->onRequest(&_Request);
			free(_Connection->method);
			free(_Connection->url);
			_Connection->url = NULL;
			_Connection->method = NULL;
		}
	}
	
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
