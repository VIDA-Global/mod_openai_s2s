#include "parser.hpp"
#include <switch.h>

cJSON* parse_json(switch_core_session_t* session, const std::string& str) {
  cJSON* json = NULL;
  json = cJSON_Parse(str.c_str());
  if (!json) {
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "parse - failed parsing incoming msg as JSON: %s\n", str.c_str());
    return NULL;
  }

/*
  const char *szType = cJSON_GetObjectCstr(json, "type");
  if (szType) {
    type.assign(szType);
  }
  else {
    type.assign("json");
  }
*/
  return json;
}
