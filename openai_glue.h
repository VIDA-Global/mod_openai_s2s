#ifndef __OPENAI_GLUE_H__
#define __OPENAI_GLUE_H__

/* utility function */
char* process_json_string(const char* str);

switch_status_t openai_s2s_init();
switch_status_t openai_s2s_cleanup();
switch_bool_t openai_s2s_read_frame(switch_core_session_t *session, switch_media_bug_t *bug, void* user_data);
switch_bool_t openai_s2s_write_frame(switch_media_bug_t *bug, void* user_data);

switch_status_t openai_s2s_session_create(switch_core_session_t *session, responseHandler_t responseHandler, 
		uint32_t samples_per_second, const char* bugname, 
    const char* host, const char *path, const char*authType, const char *apiKey, void **ppUserData);

switch_status_t openai_s2s_session_delete(switch_core_session_t *session, const char* bugname, int channelIsClosing);

switch_status_t openai_s2s_send_client_event(switch_core_session_t *session, const char* bugname, cJSON* json);

#endif