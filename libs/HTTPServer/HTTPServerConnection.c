#include "HTTPServerConnection.h"
#include <stdlib.h>
#include <stdio.h>

//-----------------Internal Functions-----------------

void HTTPServerConnection_TaskWork(void* _Context, uint64_t _MonTime);

//----------------------------------------------------

int HTTPServerConnection_Initiate(HTTPServerConnection* _Connection, int _FD)
{
	TCPClient_Initiate(&_Connection->tcpClient, _FD);

	_Connection->context = NULL;
	_Connection->onRequest = NULL;

	_Connection->method = NULL;
	_Connection->url = NULL;
	_Connection->version = NULL;
	_Connection->body = NULL;
	
	_Connection->state = HTTPServerConnection_State_Init;

	_Connection->lineLength = 0;

	_Connection->task = smw_createTask(_Connection, HTTPServerConnection_TaskWork);

	printf("HTTPServerConnection initiated on FD %d\n", _FD);

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
	
	/*
		GET /index.html HTTP/1.1\r\n
		Host: example.com\r\n

	*/

	switch(_Connection->state)
	{
		case HTTPServerConnection_State_Init:
		{
			_Connection->lineLength = 0;
			_Connection->state = HTTPServerConnection_State_ReadFirstLine;
		} break;

		case HTTPServerConnection_State_ReadFirstLine:
		{
			uint8_t buffer[HTTPServer_BufferSize];

			//Read up to max sizeof(buffer) bytes into buffer.
			int bytesRead = TCPClient_Read(&_Connection->tcpClient, buffer, sizeof(buffer));
			if(bytesRead > 0) // <= 0 connection not fully established yet
			{
				int i;
				for(i = 0; i < bytesRead; i++)
				{
					if(buffer[i] == '\n') //Is this the end of a line?
					{
						//Do we have at least one byte in our line buffer and is the last byte '\r'?
						if(_Connection->lineLength > 0 && _Connection->lineBuffer[_Connection->lineLength - 1] == '\r')
						{
							//First line found!
							_Connection->lineBuffer[_Connection->lineLength - 1] = 0; //Null terminate the entire line without \r\n

							printf("HTTPServerConnection(%d): First line: %s\n", _Connection->tcpClient.fd, _Connection->lineBuffer);
							//TODO: Parse the string extracting method, url and HTTP version

							//TODO: Copy the remaining stack buffer to a temporary buffer for further processing
							_Connection->state = HTTPServerConnection_State_ReadHeaders;
						}
						else
						{
							//Invalid first line! Disconnect and maybe ban?
							_Connection->state = HTTPServerConnection_State_InvalidRequest;
							break;
						}
					}
					else 
					{	//Continue inserting each byte of the first row
						_Connection->lineBuffer[_Connection->lineLength++] = buffer[i];	
					}
				}
			}


		} break;

		case HTTPServerConnection_State_ReadHeaders:
		{

		} break;

		case HTTPServerConnection_State_InvalidRequest:
		{

		} break;

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
