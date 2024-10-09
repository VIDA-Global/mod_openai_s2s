# mod_openai_s2s

A Freeswitch module that integrates with OpenAI realtime speech-to-speech service.

## API

### Commands
The freeswitch module exposes the following API commands:

```
uuid_openai_s2s <uuid> session.create host path auth-type [api-key]
```
where:
- host: URL host value for the websocket connection (e.g. api.openai.com)
- path: URL path (e.g. v1/realtime?model=gpt-4o-realtime-preview-2024-10-01)
- auth-type: bearer or query, indicating whether to provide api key in Authorization header or query params in URL
- api-key: the api key to use to authenticate

This api call establishes a websocket connection to the openai realtime beta (supports connecting to either OpenAI or Azure).  If the connection is successfully established, which the caller will know through the 'openai_s2s::connect' event, then the caller must next send first a `session.create` and then a `session.update` client event to the server.  Only when the first `session.update` request is sent will input audio begin streaming to the openAI endpoint.  Client events are sent using the `client_event` api described below.

```
uuid_openai_s2s <uuid> client.event client-event-json
```
where
- client-event-json: a json string conforming to the [syntax described here](https://platform.openai.com/docs/guides/realtime/client-events).

```
uuid_openai_s2s <uuid> session.delete
```
Ends the session.

### Events
This module fires the following events:
- openai_s2s::connect - fired when the websocket connection is established
- openai_s2s::connect_failed - fired if the websocket connection fails
- openai_s2s:server_event - fired when a server event is received from openai

## Basic overview of operation

The calling application first connects to the service using the `session.create` command above. Upon receiving an event indicating that the connection has been established, the caller should next use the `client.event` command to send an initial "response.create" json payload, e.g. a jsonified string such as:

```js
{
  type: 'response.create'
  response: {
    modalities: ['text', 'audio'],
    instructions: 'Please assist the user with their request.',
    voice: 'alloy',
    output_audio_format: 'pcm16',
    temperature: 0.8,
    max_output_tokens: 4096,  
  }
}
```

After sending the initial "response.create", the caller should also send a "session.update" using the `client.event` command, e.g.

```js
{
  type: 'session.update',
  session: {
      input_audio_transcription: {
        model: 'whisper-1',
      },
      turn_detection: {
        type: 'server_vad',
        threshold: 0.8,
        prefix_padding_ms: 300,
        silence_duration_ms: 500,
      },
      tools: [
        {
          name: 'get_weather',
          type: 'function',
          description: 'Get the weather at a given location',
          parameters: {
            type: 'object',
            properties: {
              location: {
                type: 'string',
                description: 'Location to get the weather from',
              },
              scale: {
                type: 'string',
                enum: ['fahrenheit', 'celsius'],
              },
            },
            required: ['location', 'scale'],
          },
        },
      ],
      tool_choice: 'auto'
    }
  }
}
```

At that point, input audio will begin streaming to openai, and any output audio received will be played to the caller.

#### Interruptions
Interruptions are handled by the module; when the caller begins speaking and openai returns an "input_audio_buffer.speech_started" event while we are playing out audio, the module automatically sends a "response.cancel" to open ai and flushes any queued audio.

### Tool calls
It is up to the caller to implement any tool calls.  The caller should listen for server events of type "response.output_item.done" with a type property of "function_call" and invoke the appropriate functionality according to the arguments provided.  Once the tool or function has completed, the caller should send first a "conversation.item.create" server event with an item.type of "function_call_output" and then should also "response.create" server event, [as described here](https://platform.openai.com/docs/guides/realtime/function-calls).