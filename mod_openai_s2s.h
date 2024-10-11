#ifndef __MOD_OPENAI_S2S_H__
#define __MOD_OPENAI_S2S_H__

#include <switch.h>
#include <speex/speex_resampler.h>

#include <unistd.h>

#define MY_BUG_NAME "openai_s2s"

#define OAIS2S_EVENT_SERVER "openai_s2s::server_event"

#define OAIS2S_EVENT_VAD_DETECTED "openai_s2s::vad_detected"
#define OAIS2S_EVENT_CONNECT_SUCCESS "openai_s2s::connect"
#define OAIS2S_EVENT_CONNECT_FAIL    "openai_s2s::connect_failed"
#define OAIS2S_EVENT_BUFFER_OVERRUN  "openai_s2s::buffer_overrun"
#define OAIS2S_EVENT_DISCONNECT      "openai_s2s::disconnect"

#define MAX_SESSION_ID (256)
#define MAX_PARM_LEN (4096)
#define MAX_BUG_LEN (64)

typedef void (*responseHandler_t)(switch_core_session_t* session, const char* eventName, const char* json, const char* bugname);

typedef enum {
    SESSION_STATE_NONE = 0,
    SESSION_STATE_WS_CONNECTED,
    SESSION_STATE_CONVERSATION_STARTED
} SessionState_t;


struct private_data {
	switch_mutex_t *mutex;
	char sessionId[MAX_SESSION_ID+1];
  char bugname[MAX_BUG_LEN+1];
  SessionState_t state;
  SpeexResamplerState *resampler_in;
  responseHandler_t responseHandler;
  void *pAudioPipe;
  int ws_state;
  int sampling;
  unsigned int id;
  int buffer_overrun_notified:1;
  int is_finished:1;
  int user_is_speaking:1;
  int asssistant_is_speaking:1;
  int process_interrupt:1;
  int initial_session_updated_received:1;

  // audio output
  void *audioPlayer;
  void *playoutBuffer;
};

typedef struct private_data private_t;

#endif