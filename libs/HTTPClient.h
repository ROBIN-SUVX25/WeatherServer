#ifndef HTTPClient_h
#define HTTPClient_h

typedef enum
{
	HTTPClient_State_Init,
	HTTPClient_State_Connect,
	HTTPClient_State_Transmit,
	HTTPClient_State_Receive,
	HTTPClient_State_Close

} HTTPClient_State;


typedef struct
{
	void (*callback)(HTTPClient* _CLient, const char* _Event);
	uint8_t* buffer;
	uint8_t* bufferPtr;

	smw_task* task;

} HTTPClient;



int HTTPClient_Initiate(HTTPClient* _Client);

int HTTPClient_GET(HTTPClient* _Client, const char* _URL, void (*callback)(HTTPClient* _CLient, const char* _Event));

void HTTPClient_Dispose(HTTPClient* _Client);



#endif //HTTPClient_h