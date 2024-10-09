/* 
 *
 * mod_openai_s2s.c -- Freeswitch module for using open ai speech to speech api
 *
 */
#include "mod_openai_s2s.h"
#include "openai_glue.h"
#include <stdio.h>
#include <stdbool.h>

/* Prototypes */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_openai_s2s_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_openai_s2s_load);
SWITCH_MODULE_DEFINITION(mod_openai_s2s, mod_openai_s2s_load, mod_openai_s2s_shutdown, NULL);

static const char *valid_commands[] = {
    "session.create",
    "session.delete",
    "client.event"
};

static bool is_valid_command(const char *cmd) {
  for (int i = 0; i < sizeof(valid_commands) / sizeof(valid_commands[0]); i++) {
    if (strcasecmp(cmd, valid_commands[i]) == 0) {
      return true;
    }
  }
  return false;
}


static void responseHandler(switch_core_session_t* session, 
	const char* eventName, const char * json, const char* bugname) {
	switch_event_t *event;
	switch_channel_t *channel = switch_core_session_get_channel(session);

	switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, eventName);
	switch_channel_event_set_data(channel, event);
	switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "llm-vendor", "openai");
	if (json) switch_event_add_body(event, "%s", json);
	if (bugname) switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "media-bugname", bugname);
	switch_event_fire(&event);
}


static switch_bool_t capture_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	switch_core_session_t *session = switch_core_media_bug_get_session(bug);

	switch (type) {
	case SWITCH_ABC_TYPE_INIT:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Got SWITCH_ABC_TYPE_INIT.\n");
		break;

	case SWITCH_ABC_TYPE_CLOSE:
		{
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Got SWITCH_ABC_TYPE_CLOSE.\n");
			openai_s2s_session_delete(session, MY_BUG_NAME, 1);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Finished SWITCH_ABC_TYPE_CLOSE.\n");
		}
		break;
	
	case SWITCH_ABC_TYPE_READ:

		return openai_s2s_read_frame(session, bug, user_data);
		break;

	case SWITCH_ABC_TYPE_WRITE_REPLACE:
		return openai_s2s_write_frame(bug, user_data);
    break;
  
	default:
		break;
	}

	return SWITCH_TRUE;
}

#define OPENAI_API_SYNTAX "<uuid> [session.create|session.delete|client.event] [api_key|json]"


// uuid_openai_s2s <uuid> session.create host path auth-type [api-key]
//             auth-type: bearer, query
//
// uuid_openai_s2s <uuid> client.event client-event-json
//
// uuid_openai_s2s <uuid> session.delete

SWITCH_STANDARD_API(openai_s2s_function)
{
	char *mycmd = NULL, *argv[6] = { 0 };
	int argc = 0;
	switch_status_t status = SWITCH_STATUS_FALSE;
  switch_core_session_t *lsession = NULL;
  cJSON *json = NULL;

  switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "openai_s2s_function: %s\n", cmd);

  /* validate command */
	if (!zstr(cmd) && (mycmd = strdup(cmd))) {
		argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
	}
  if (argc < 2 || zstr(argv[1])) {
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Invalid input: Command is required.\n");
    stream->write_function(stream, "-USAGE: %s\n", OPENAI_API_SYNTAX);
    goto done;
  }
  if (zstr(cmd) || !is_valid_command(argv[1])) {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Invalid command: %s\n", argv[1]);
      stream->write_function(stream, "-USAGE: %s\n", OPENAI_API_SYNTAX);
      goto done;
  }

  if ((lsession = switch_core_session_locate(argv[0]))) {
    if (!strcasecmp(argv[1], "session.create")) {
      if (argc < 5) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, 
          "invalid syntax, use uuid_openai_s2s <uuid> session.create host path auth-type api-key session-create-json\n");
        goto done;
      }
      else {
        switch_channel_t *channel = switch_core_session_get_channel(lsession);
        switch_codec_t* read_codec = switch_core_session_get_read_codec(lsession);
        void *pUserData = NULL;
        const char* host = argv[2];
        const char* path = argv[3];
        const char* authType = argv[4];
        const char* apiKey = argc < 6 ? NULL : argv[5];
        
        switch_media_bug_flag_t flags = SMBF_READ_STREAM | SMBF_WRITE_REPLACE;

        /* there should not be a session in progress for this channel when we are trying to create one */
        if (switch_channel_get_private(channel, MY_BUG_NAME)) {
          switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "session.create: an openai session is already in progress for this channel!\n");
        }

        /* the channel must have been answered */
        else if (switch_channel_pre_answer(channel) != SWITCH_STATUS_SUCCESS) {
          switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "session.create: channel must have reached pre-answer status before calling session.create!\n");
        }

        else {
          status = openai_s2s_session_create(lsession, responseHandler, read_codec->implementation->samples_per_second, MY_BUG_NAME, 
            host, path, authType, apiKey, &pUserData);
          if (status == SWITCH_STATUS_SUCCESS) {
            switch_media_bug_t *bug = NULL;
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "adding bug %s.\n", MY_BUG_NAME);
            if (SWITCH_STATUS_SUCCESS != switch_core_media_bug_add(lsession, MY_BUG_NAME, NULL, capture_callback, pUserData, 0, flags, &bug)) {
              switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "session.create: failed to add media bug!\n");
              openai_s2s_session_delete(lsession, MY_BUG_NAME, 0);
            }
            else {
              switch_channel_set_private(channel, MY_BUG_NAME, bug);
            }
          }
        }
      }
    }
    else if (!strcasecmp(argv[1], "session.delete")) {
      return openai_s2s_session_delete(lsession, MY_BUG_NAME, 0);
    }
    else if (!strcasecmp(argv[1], "client.event")) {
      const char* str = argv[2];
      json = cJSON_Parse(str);
      if (!json) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "session.update: failed parsing incoming msg as JSON: %s\n", argv[2]);
        status = SWITCH_STATUS_FALSE;
      }
      else {
        status = openai_s2s_send_client_event(lsession, MY_BUG_NAME, json);
        cJSON_Delete(json);
      }
    }
    switch_core_session_rwunlock(lsession);
  }

	if (status == SWITCH_STATUS_SUCCESS) {
		stream->write_function(stream, "+OK Success\n");
	} else {
		stream->write_function(stream, "-ERR Operation Failed\n");
	}

  done:

	switch_safe_free(mycmd);
	return SWITCH_STATUS_SUCCESS;
}


SWITCH_MODULE_LOAD_FUNCTION(mod_openai_s2s_load)
{
	switch_api_interface_t *api_interface;

	/* create/register custom event message type */
	if (switch_event_reserve_subclass(OAIS2S_EVENT_SERVER) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!\n", OAIS2S_EVENT_SERVER);
		return SWITCH_STATUS_TERM;
	}
	if (switch_event_reserve_subclass(OAIS2S_EVENT_VAD_DETECTED) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!\n", OAIS2S_EVENT_VAD_DETECTED);
		return SWITCH_STATUS_TERM;
	}
	if (switch_event_reserve_subclass(OAIS2S_EVENT_CONNECT_SUCCESS) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!\n", OAIS2S_EVENT_CONNECT_SUCCESS);
		return SWITCH_STATUS_TERM;
	}
	if (switch_event_reserve_subclass(OAIS2S_EVENT_CONNECT_FAIL) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!\n", OAIS2S_EVENT_CONNECT_FAIL);
		return SWITCH_STATUS_TERM;
	}
	if (switch_event_reserve_subclass(OAIS2S_EVENT_BUFFER_OVERRUN) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!\n", OAIS2S_EVENT_BUFFER_OVERRUN);
		return SWITCH_STATUS_TERM;
	}
	if (switch_event_reserve_subclass(OAIS2S_EVENT_DISCONNECT) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!\n", OAIS2S_EVENT_DISCONNECT);
		return SWITCH_STATUS_TERM;
	}

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "OpenAI speech to speech API loading..\n");

  if (SWITCH_STATUS_FALSE == openai_s2s_init()) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Failed initializing dg speech interface\n");
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "OpenAI speech to speech API successfully loaded\n");

	SWITCH_ADD_API(api_interface, "uuid_openai_s2s", "OpenAI speech to speech API", openai_s2s_function, OPENAI_API_SYNTAX);
	switch_console_set_complete("add uuid_openai_s2s start lang-code [interim|final] [stereo|mono]");
	switch_console_set_complete("add uuid_openai_s2s stop ");

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_openai_s2s_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_openai_s2s_shutdown)
{
	openai_s2s_cleanup();
	switch_event_free_subclass(OAIS2S_EVENT_SERVER);
	switch_event_free_subclass(OAIS2S_EVENT_VAD_DETECTED);
	switch_event_free_subclass(OAIS2S_EVENT_CONNECT_SUCCESS);
	switch_event_free_subclass(OAIS2S_EVENT_CONNECT_FAIL);
	switch_event_free_subclass(OAIS2S_EVENT_BUFFER_OVERRUN);
	switch_event_free_subclass(OAIS2S_EVENT_DISCONNECT);
	return SWITCH_STATUS_SUCCESS;
}
