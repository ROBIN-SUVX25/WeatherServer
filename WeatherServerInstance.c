#include "WeatherServerInstance.h"
#include <stdlib.h>

//-----------------Internal Functions-----------------

int WeatherServerInstance_OnRequest(void* _Context);

//----------------------------------------------------

int WeatherServerInstance_Initiate(WeatherServerInstance* _Instance, HTTPServerConnection* _Connection)
{
	_Instance->connection = _Connection;

	HTTPServerConnection_SetCallback(_Instance->connection, _Instance, WeatherServerInstance_OnRequest);

	return 0;
}

int WeatherServerInstance_InitiatePtr(HTTPServerConnection* _Connection, WeatherServerInstance** _InstancePtr)
{
	if(_InstancePtr == NULL)
		return -1;

	WeatherServerInstance* _Instance = (WeatherServerInstance*)malloc(sizeof(WeatherServerInstance));
	if(_Instance == NULL)
		return -2;

	int result = WeatherServerInstance_Initiate(_Instance, _Connection);
	if(result != 0)
	{
		free(_Instance);
		return result;
	}

	*(_InstancePtr) = _Instance;

	return 0;
}

int WeatherServerInstance_OnRequest(void* _Context)
{
	if (!_Context) {
		return -1;
	}
	
	HTTPServerConnection* _Connection = (HTTPServerConnection*)_Context;
	if (!_Connection || !_Connection->method || !_Connection->url) {
		return -1;
	}

	printf("Method: %s\r\n", _Connection->method);
	printf("URL: %s\r\n", _Connection->url);
	
	printf("WeatherServerInstance_OnRequest\n");
	
	return 0;
}

void WeatherServerInstance_Work(WeatherServerInstance* _Server, uint64_t _MonTime)
{
	
}

void WeatherServerInstance_Dispose(WeatherServerInstance* _Instance)
{

}

void WeatherServerInstance_DisposePtr(WeatherServerInstance** _InstancePtr)
{
	if(_InstancePtr == NULL || *(_InstancePtr) == NULL)
		return;

	WeatherServerInstance_Dispose(*(_InstancePtr));
	free(*(_InstancePtr));
	*(_InstancePtr) = NULL;
}
