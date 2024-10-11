#include <switch.h>
#include <switch_json.h>
#include <string.h>
#include <string>
#include <list>
#include <algorithm>
#include <functional>
#include <cassert>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <regex>
#include <iostream>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <atomic>
#include <cstring>

//TMP!!
#include <fstream>


#include <boost/circular_buffer.hpp>
#include <boost/algorithm/string/replace.hpp>

#include "mod_openai_s2s.h"
#include "simple_buffer.h"
#include "parser.hpp"
#include "audio_pipe.hpp"
#include "base64.hpp"
#include "vector_math.h"

typedef boost::circular_buffer<uint16_t> CircularBuffer_t;

#define RTP_PACKETIZATION_PERIOD 20
#define FRAME_SIZE_8000  320 /*which means each 20ms frame as 320 bytes at 8 khz (1 channel only)*/
#define BUFFER_GROW_SIZE (16384)

namespace {
  static const char *requestedBufferSecs = std::getenv("MOD_AUDIO_FORK_BUFFER_SECS");
  static int nAudioBufferSecs = std::max(1, std::min(requestedBufferSecs ? ::atoi(requestedBufferSecs) : 2, 5));
  static const char *requestedNumServiceThreads = std::getenv("MOD_AUDIO_FORK_SERVICE_THREADS");
  static unsigned int idxCallCount = 0;
  static uint32_t playCount = 0;

  static std::ofstream audio_file("/tmp/raw_audio_data.bin", std::ios::binary | std::ios::app);

  // Function to write raw audio data to file

  void writeRawAudioToFile(const uint8_t* buffer, size_t datalen) {
    if (audio_file.is_open()) {
      audio_file.write(reinterpret_cast<const char*>(buffer), datalen);
    } else {
      switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to open raw_audio_data.bin for writing.\n");
    }
  }

  // Function to escape newlines, quotes, and backslashes in a string (for JSON) using Boost
  std::string escape_json_content(const std::string& input) {
    std::string escaped = input;      
    boost::replace_all(escaped, "\\", "\\\\"); // Escape backslashes first
    boost::replace_all(escaped, "\"", "\\\""); // Escape double quotes
    boost::replace_all(escaped, "\n", "\\n");  // Escape newlines
    return escaped;
  }

  // Function to find the end of a JSON string value, handling escaped quotes
  size_t find_closing_quote(const std::string& json_input, size_t start_pos) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "instructions content starting at %d: %s\n", start_pos, json_input.c_str() + start_pos);
    bool escape = false;
    for (size_t i = start_pos; i < json_input.length(); ++i) {
      if (escape) {
        escape = false;  // Skip the escaped character
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "skipping escaped char at %d\n", i);

      } else if (json_input[i] == '\\') {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "found backslash at %d, setting escaped mode\n", i);
        escape = true;  // Set escape mode for the next character
      } else if (json_input[i] == '"') {
        // Ensure it's an unescaped quote before returning
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "found quote at %d\n", i);
        if (!escape) {
          switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "found final quote at %d, returning\n", i);
          return i;  // Unescaped quote found, return its position
        }
      }
    }
    return std::string::npos;  // No closing quote found
  }

  class AudioPlayer {
  public:
    AudioPlayer(private_t* p, int sampleRate = 8000) : 
    done(false), tech_pvt(p), desiredSampleRate(sampleRate) {
      // Start the consumer thread when the object is created
      consumer_thread = std::thread(&AudioPlayer::consumeAudio, this);
      resampler = speex_resampler_init(1, 24000, sampleRate, SWITCH_RESAMPLE_QUALITY, NULL);
    }

    ~AudioPlayer() {
      switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "AudioPlayer::~AudioPlayer joining thread\n");
      finish();  // Ensure the consumer thread finishes before the object is destroyed
      consumer_thread.join();
      switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "AudioPlayer::~AudioPlayer joined thread\n");
    }

    // Buffers base64 encoded audio
    void bufferAudio(const char* base64Audio, size_t length) {
      std::lock_guard<std::mutex> lock(buffer_mutex);
      buffer.insert(buffer.end(), base64Audio, base64Audio + length);

      // Notify the consumer that new data is available
      data_ready_cv.notify_one();
    }

    // Clears the audio buffer
    void clear() {
      std::lock_guard<std::mutex> lock(buffer_mutex);
      buffer.clear();
    }

    // Signals the thread to finish and stops audio consumption
    void finish() {
      std::lock_guard<std::mutex> lock(buffer_mutex);
      done = true;
      data_ready_cv.notify_one();  // Wake up the consumer to allow it to exit
    }

  private:
    std::vector<char> buffer;               // Buffer to hold the audio data
    std::mutex buffer_mutex;                // Mutex to protect buffer access
    std::condition_variable data_ready_cv;  // Condition variable to signal data readiness
    std::thread consumer_thread;            // Thread for consuming audio
    std::atomic<bool> done;                 // Flag to signal the end of processing
    SpeexResamplerState *resampler;         // resample from 24k to 8k
    int desiredSampleRate;
    private_t* tech_pvt;

    // Consumer function to process audio from the buffer
    void consumeAudio() {
      const size_t CHUNK_SIZE = 12000;
      while (true) {
        std::unique_lock<std::mutex> lock(buffer_mutex);

        // Wait until data is ready or the producer is done
        data_ready_cv.wait(lock, [this] { return !buffer.empty() || done; });

        if (!buffer.empty()) {
          std::string audioData(buffer.begin(), buffer.end());
          buffer.clear();  // Clear the buffer after processing
          lock.unlock();   // Unlock to allow further buffering

          // Decode the base64 audio data to raw 24k pcm
          std::string rawData = drachtio::base64_decode(audioData);

          //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Got %ld bytes of 24k pcm audio.\n", rawData.size());

          size_t dataSize = rawData.size();
          size_t processed = 0;

          // Calculate number of samples per chunk (since each sample is 16 bits or 2 bytes)
          size_t samplesPerChunk = CHUNK_SIZE / 2;  // 16-bit audio, so 2 bytes per sample

          do {
            // Calculate remaining bytes to process
            size_t remaining = dataSize - processed;
            size_t chunkSize = std::min(CHUNK_SIZE, remaining);

            // Calculate the number of input samples for this chunk (2 bytes per sample)
            size_t inSamples = chunkSize / 2;
            size_t outSamples = (inSamples * desiredSampleRate) / 24000;

            // Allocate buffers for input and output
            const spx_int16_t* input = reinterpret_cast<const spx_int16_t*>(rawData.data() + processed);
            std::vector<spx_int16_t> output(outSamples);  // Buffer for resampled output

            // Resample the current chunk
            spx_uint32_t in_len = inSamples;
            spx_uint32_t out_len = outSamples;

            speex_resampler_process_int(resampler, 0,
              input, 
              &in_len, 
              output.data(),
              &out_len);

            //switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Processed %ld input samples to %ld output samples.\n", in_len, out_len);

            //writeRawAudioToFile(reinterpret_cast<const uint8_t*>(output.data()), out_len * sizeof(int16_t));

            // at this point we need to grab the session mutex and push the 8k samples into the circular buffer
            size_t out_size_bytes = out_len * 2;
            CircularBuffer_t *cBuffer = (CircularBuffer_t *) tech_pvt->playoutBuffer;
            switch_mutex_lock(tech_pvt->mutex);
            if (cBuffer->capacity() - cBuffer->size() < out_size_bytes) {
              size_t newCapacity = cBuffer->size() + std::max(out_size_bytes, (size_t)BUFFER_GROW_SIZE);
              cBuffer->set_capacity(newCapacity);
            }
            cBuffer->insert(cBuffer->end(), output.begin(), output.end());

            switch_mutex_unlock(tech_pvt->mutex);

            // Update the number of bytes processed
            processed += chunkSize;

          } while (processed < dataSize);
        } else if (done) {
          switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "AudioPlayer consume thread exiting\n");
          break;
        }
      }
    }
  };

  static void destroy_tech_pvt(private_t *tech_pvt) {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s (%u) destroy_tech_pvt\n", tech_pvt->sessionId, tech_pvt->id);
    if (tech_pvt) {
      if (tech_pvt->resampler_in) {
          speex_resampler_destroy(tech_pvt->resampler_in);
          tech_pvt->resampler_in = nullptr;
      }
      if (tech_pvt->audioPlayer) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "destroying audio player\n");
        AudioPlayer* p = static_cast<AudioPlayer*>(tech_pvt->audioPlayer);
        delete p;
        tech_pvt->audioPlayer = nullptr;
      }
      if (tech_pvt->playoutBuffer) {
        CircularBuffer_t *cBuffer = (CircularBuffer_t *) tech_pvt->playoutBuffer;
        delete cBuffer;
        tech_pvt->playoutBuffer = nullptr;
      }
      if (tech_pvt->mutex) {
        switch_mutex_destroy(tech_pvt->mutex);
        tech_pvt->mutex = nullptr;
      }
    }
  }

  static void processIncomingAudio(private_t* tech_pvt, switch_core_session_t* session, const char* base64_data) {
    AudioPlayer* p = static_cast<AudioPlayer*>(tech_pvt->audioPlayer);
    p->bufferAudio(base64_data, strlen(base64_data));
  }

  static void handleInterruption(private_t* tech_pvt, switch_core_session_t* session) {
    AudioPlayer* p = static_cast<AudioPlayer*>(tech_pvt->audioPlayer);
    tech_pvt->process_interrupt = true;
    p->clear();
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "interrupt the assistant\n");
  }

  static void eventCallback(const char* sessionId, const char* bugname, 
    openai_s2s::AudioPipe::NotifyEvent_t event, const char* message) {
    switch_core_session_t* session = switch_core_session_locate(sessionId);
    if (session) {
      switch_channel_t *channel = switch_core_session_get_channel(session);
      switch_media_bug_t *bug = (switch_media_bug_t*) switch_channel_get_private(channel, bugname);
      if (bug) {
        private_t* tech_pvt = (private_t*) switch_core_media_bug_get_user_data(bug);
        if (tech_pvt) {
          switch (event) {
            case openai_s2s::AudioPipe::CONNECT_SUCCESS:
              tech_pvt->state = SESSION_STATE_WS_CONNECTED;
              switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "connection (%s) successful\n", tech_pvt->bugname);
              tech_pvt->responseHandler(session, OAIS2S_EVENT_CONNECT_SUCCESS, NULL, tech_pvt->bugname);
            break;
            case openai_s2s::AudioPipe::CONNECT_FAIL:
              tech_pvt->state = SESSION_STATE_NONE;
              {
                // first thing: we can no longer access the AudioPipe
                std::stringstream json;
                json << "{\"reason\":\"" << message << "\"}";
                tech_pvt->pAudioPipe = nullptr;
                tech_pvt->responseHandler(session, OAIS2S_EVENT_CONNECT_FAIL, (char *) json.str().c_str(), tech_pvt->bugname);
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "connection (%s) failed: %s\n", message, tech_pvt->bugname);
              }
            break;
            case openai_s2s::AudioPipe::CONNECTION_DROPPED:
              tech_pvt->state = SESSION_STATE_NONE;

              // first thing: we can no longer access the AudioPipe
              tech_pvt->pAudioPipe = nullptr;
              tech_pvt->responseHandler(session, OAIS2S_EVENT_DISCONNECT, NULL, tech_pvt->bugname);
              switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "connection (%s) dropped from far end\n", tech_pvt->bugname);
            break;
            case openai_s2s::AudioPipe::CONNECTION_CLOSED_GRACEFULLY:
              tech_pvt->state = SESSION_STATE_NONE;

              // first thing: we can no longer access the AudioPipe
              tech_pvt->pAudioPipe = nullptr;
              switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "connection (%s) closed gracefully\n", tech_pvt->bugname);
            break;
            case openai_s2s::AudioPipe::MESSAGE:
            {
              cJSON* json = parse_json(session, message) ;
              if (!json) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "failed to parse json for message %s\n", message);
              }
              else {
                bool forward = true;
                const char* type = cJSON_GetObjectCstr(json, "type");

                // when the conversation starts, we can start streaming audio to the server
                if (0 == strcmp(type, "session.created") && tech_pvt->state != SESSION_STATE_CONVERSATION_STARTED) {
                  switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "got first session.created\n");
                }
                else if (0 == strcmp(type, "session.updated") && !tech_pvt->initial_session_updated_received) {
                  tech_pvt->initial_session_updated_received = true;
                  tech_pvt->state = SESSION_STATE_CONVERSATION_STARTED;
                  switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "got first session.updated\n");
                }
                else if (0 == strcmp(type, "response.audio.delta")) {
                  forward = false;
                   if (!tech_pvt->asssistant_is_speaking) {
                    tech_pvt->asssistant_is_speaking = true;
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "assistant started speaking\n");
                   }
                  processIncomingAudio(tech_pvt, session, cJSON_GetObjectCstr(json, "delta"));
                }
                else if (0 == strcmp(type, "input_audio_buffer.speech_started")) {
                  /**
                   * https://platform.openai.com/docs/guides/realtime/handling-interruptions
                   * 
                   * keep state of when user is talking and when model is sending audio
                   * if user starts talking while model is sending audio, send response.cancel
                   * and clear any buffered audio.  Furthermore, any stray audio that comes in
                   * should be ignored until we get input_audio_buffer.committed
                   */
                  if (tech_pvt->asssistant_is_speaking) {
                    handleInterruption(tech_pvt, session);
                  }
                  tech_pvt->user_is_speaking = true;
                }
                else if (0 == strcmp(type, "input_audio_buffer.speech_stopped")) {
                  tech_pvt-> user_is_speaking = false;
                }
                else if (0 == strcmp(type, "input_audio_buffer.committed")) {
                }
                else if (0 == strcmp(type, "response.audio.done")) {
                  forward = false;
                  tech_pvt->asssistant_is_speaking = false;
                  switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "assistant stopped sending audio\n");
                }

                if (forward) {
                  switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "openai server event (%s): %s\n", tech_pvt->bugname, message);
                  tech_pvt->responseHandler(session, OAIS2S_EVENT_SERVER, message, tech_pvt->bugname);
                }

                cJSON_Delete(json);
              }
            }
            break;

            default:
              switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_NOTICE, "got unexpected msg from openai %d:%s\n", event, message);
              break;
          }
        }
      }
      else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "event callback sessionId %s bugname %s not found for message %s\n", sessionId, bugname, message);
      }
      switch_core_session_rwunlock(session);
    }
    else {
    }
  }
  switch_status_t fork_data_init(private_t *tech_pvt, switch_core_session_t *session, int sampling, 
    const char* host, const char *path, const char* authType, const char* apiKey, 
    responseHandler_t responseHandler) {
    int err;
    int channels = 1;
    int desiredSampling = 24000; // https://platform.openai.com/docs/guides/realtime/audio-formats - 24k L16 pcm
    std::string fullPath = path;
    bool useAuthHeader = (0 != strcmp(authType, "query"));

    if (!useAuthHeader && std::string::npos == fullPath.find("?api-key=") && apiKey) {
      // append api key to path if not there and we are using query args to authenticate
      fullPath += "&api-key=";
      fullPath += apiKey;
    }
    int port = 443;
    size_t buflen = LWS_PRE + (FRAME_SIZE_8000 * desiredSampling / 8000 * channels * 1000 / RTP_PACKETIZATION_PERIOD * nAudioBufferSecs);

    switch_codec_implementation_t read_impl;
    switch_channel_t *channel = switch_core_session_get_channel(session);

    switch_core_session_get_read_impl(session, &read_impl);
  
    openai_s2s::AudioPipe* ap = new openai_s2s::AudioPipe(tech_pvt->sessionId, tech_pvt->bugname, host, port, path, 
      buflen, read_impl.decoded_bytes_per_packet, useAuthHeader ? apiKey : nullptr, eventCallback);
    if (!ap) {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error allocating AudioPipe\n");
      return SWITCH_STATUS_FALSE;
    }

    tech_pvt->pAudioPipe = static_cast<void *>(ap);
    tech_pvt->audioPlayer = (void *) new AudioPlayer(tech_pvt, sampling);
    tech_pvt->playoutBuffer = (void *) new CircularBuffer_t(8192);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "connecting now\n");
    ap->connect();
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "connection in progress\n");

    switch_mutex_init(&tech_pvt->mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));
    
    if (desiredSampling != sampling) {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "(%u) resampling user audio from %u to %u\n", tech_pvt->id, sampling, desiredSampling);
      tech_pvt->resampler_in = speex_resampler_init(1, sampling, desiredSampling, SWITCH_RESAMPLE_QUALITY, &err);
      if (0 != err) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error initializing resampler: %s.\n", speex_resampler_strerror(err));
        return SWITCH_STATUS_FALSE;
      }
    }
    else {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "(%u) no resampling needed for this call\n", tech_pvt->id);
    }

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "(%u) fork_data_init\n", tech_pvt->id);

    return SWITCH_STATUS_SUCCESS;
  }

  void lws_logger(int level, const char *line) {
    switch_log_level_t llevel = SWITCH_LOG_DEBUG;

    switch (level) {
      case LLL_ERR: llevel = SWITCH_LOG_ERROR; break;
      case LLL_WARN: llevel = SWITCH_LOG_WARNING; break;
      case LLL_NOTICE: llevel = SWITCH_LOG_NOTICE; break;
      case LLL_INFO: llevel = SWITCH_LOG_INFO; break;
      break;
    }
	  switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "%s\n", line);
  }
}


extern "C" {

  // utility function to properly escape "instructions" property in response.create
  char* process_json_string(const char* str) {
    std::string json_input(str);  // Convert C string to std::string
    const std::string instructions_key = "\"instructions\":\"";
    size_t instructions_start = json_input.find(instructions_key);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "processing %s\n", str);

    if (instructions_start == std::string::npos) {
      // "instructions" field not found, return original string (copy)
      switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "instructions not found\n");

      char* result = (char*)malloc(strlen(str) + 1);
      strcpy(result, str);
      return result;
    }

    // Move to the start of the "instructions" value
    instructions_start += instructions_key.length();

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "found instructions at %d\n", instructions_start);

    // Find the closing quote of the instructions value, handling escaped quotes
    size_t instructions_end = find_closing_quote(json_input, instructions_start);
    if (instructions_end == std::string::npos) {
        // Malformed JSON (no closing quote for "instructions"), return the original string
        char* result = (char*)malloc(strlen(str) + 1);
        strcpy(result, str);
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "failed to find closing quote\n");
        return result;
    }

    // Extract the original instructions value
    std::string original_instructions = json_input.substr(instructions_start, instructions_end - instructions_start);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "found closing quote at %d\n", instructions_end);
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "extracted %s\n", original_instructions.c_str());

    // Escape the instructions content using Boost
    std::string escaped_instructions = escape_json_content(original_instructions);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "rebuilt to %s\n", escaped_instructions.c_str());

    // Rebuild the JSON string
    std::string new_json = json_input.substr(0, instructions_start) + escaped_instructions + json_input.substr(instructions_end);

    // Convert std::string back to char* and return
    char* result = (char*)malloc(new_json.size() + 1);
    strcpy(result, new_json.c_str());
    return result;
  }

  switch_status_t openai_s2s_init() {
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_speechmatics_transcribe: audio buffer (in secs):    %d secs\n", nAudioBufferSecs);
 
    int logs = LLL_ERR | LLL_WARN | LLL_NOTICE;
    // | LLL_INFO | LLL_PARSER | LLL_HEADER | LLL_EXT | LLL_CLIENT  | LLL_LATENCY | LLL_DEBUG ;
    
    openai_s2s::AudioPipe::initialize(logs, lws_logger);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "AudioPipe::initialize completed\n");

		return SWITCH_STATUS_SUCCESS;
  }

  switch_status_t openai_s2s_cleanup() {
    bool cleanup = false;
    cleanup = openai_s2s::AudioPipe::deinitialize();
    if (cleanup == true) {
        return SWITCH_STATUS_SUCCESS;
    }
    return SWITCH_STATUS_FALSE;
  }
	
  switch_status_t openai_s2s_session_create(switch_core_session_t *session, responseHandler_t responseHandler, 
		uint32_t samples_per_second, const char* bugname, 
    const char* host, const char *path, const char*authType,const char* apiKey, void **ppUserData)
  {
    int err;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_media_bug_t *bug = (switch_media_bug_t*) switch_channel_get_private(channel, bugname);
    private_t* tech_pvt;

    if (bug) {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "openai_s2s_session_create failed because connection already in progress\n");
      return SWITCH_STATUS_FALSE;
    }
    
    tech_pvt = (private_t *) switch_core_session_alloc(session, sizeof(private_t));
    if (!tech_pvt) {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "error allocating memory!\n");
      return SWITCH_STATUS_FALSE;
    }
    memset(tech_pvt, 0, sizeof(private_t));
    strncpy(tech_pvt->sessionId, switch_core_session_get_uuid(session), MAX_SESSION_ID);
    strncpy(tech_pvt->bugname, bugname, MAX_BUG_LEN);
    tech_pvt->responseHandler = responseHandler;
    tech_pvt->id = ++idxCallCount;

    if (SWITCH_STATUS_SUCCESS != fork_data_init(tech_pvt, session, samples_per_second, 
      host, path, authType, apiKey, responseHandler)) {
      destroy_tech_pvt(tech_pvt);
      return SWITCH_STATUS_FALSE;
    }

    *ppUserData = tech_pvt;

    return SWITCH_STATUS_SUCCESS;
  }

  switch_status_t openai_s2s_send_client_event(switch_core_session_t *session, const char* bugname, cJSON* json) {
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_media_bug_t *bug = (switch_media_bug_t*) switch_channel_get_private(channel, bugname);
    if (!bug) {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "openai_s2s_send_client_event failed because no bug\n");
      return SWITCH_STATUS_FALSE;
    }
    private_t* tech_pvt = (private_t*) switch_core_media_bug_get_user_data(bug);
  
    if (!tech_pvt) return SWITCH_STATUS_FALSE;
    openai_s2s::AudioPipe *pAudioPipe = static_cast<openai_s2s::AudioPipe *>(tech_pvt->pAudioPipe);
    if (pAudioPipe) {
      char *json_string = nullptr;

      /* special case: when sending function_call_output the item.output needs to be jsonified string */
      const char* type = cJSON_GetObjectCstr(json, "type");
      if (type && 0 == strcmp(type, "conversation.item.create")) {
        cJSON* item = cJSON_GetObjectItem(json, "item");
        if (item) {
          // Retrieve the "type" field from the item and check if it's "function_call_output"
          cJSON* item_type = cJSON_GetObjectItem(item, "type");
          if (item_type && cJSON_IsString(item_type) && strcmp(item_type->valuestring, "function_call_output") == 0) {

            // Now check if output is an object
            cJSON* output = cJSON_GetObjectItem(item, "output");
            if (output && cJSON_IsObject(output)) {
              char* outputStr = cJSON_PrintUnformatted(output);
              if (!outputStr) {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "openai_s2s_session_update failed to serialize json\n");
                return SWITCH_STATUS_FALSE;
              }

              // Replace the "output" item with the stringified version of the object
              cJSON_ReplaceItemInObject(item, "output", cJSON_CreateString(outputStr));

              // Free the memory for the generated JSON string
              free(outputStr);
            }
          }
        }
      }

      if (nullptr == json_string) {
        json_string = cJSON_PrintUnformatted(json);
        if (0 == strcmp(type, "response.create")) {
          switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "openai_s2s_send_client_event sending response.create %s\n", json_string);
        }
      }

      if (!json_string) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "openai_s2s_send_client_event failed to serialize json\n");
        return SWITCH_STATUS_FALSE;
      }
      pAudioPipe->bufferForSending(json_string);
      free(json_string);
    }

    return SWITCH_STATUS_SUCCESS;
  }

	switch_status_t openai_s2s_session_delete(switch_core_session_t *session, const char* bugname, int channelIsClosing) {
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_media_bug_t *bug = (switch_media_bug_t*) switch_channel_get_private(channel, bugname);

    if (!bug) {
      switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "openai_s2s_session_delete: no bug - websocket conection already closed\n");
      return SWITCH_STATUS_FALSE;
    }
    private_t* tech_pvt = (private_t*) switch_core_media_bug_get_user_data(bug);
    if (!tech_pvt) return SWITCH_STATUS_FALSE;

    uint32_t id = tech_pvt->id;

    openai_s2s::AudioPipe *pAudioPipe = static_cast<openai_s2s::AudioPipe *>(tech_pvt->pAudioPipe);

    // close connection and get final responses
    switch_mutex_lock(tech_pvt->mutex);

    // get the bug again, now that we are under lock
    {
      switch_media_bug_t *bug = (switch_media_bug_t*) switch_channel_get_private(channel, bugname);
      if (bug) {
        switch_channel_set_private(channel, bugname, NULL);
        if (!channelIsClosing) {
          switch_core_media_bug_remove(session, &bug);
        }
      }
    }

    if (pAudioPipe) pAudioPipe->close();
    destroy_tech_pvt(tech_pvt);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "(%u) openai_s2s_session_delete complete\n", id);
    return SWITCH_STATUS_SUCCESS;
  }
	
  switch_bool_t openai_s2s_write_frame(switch_media_bug_t *bug, void* user_data) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    private_t* tech_pvt = (private_t*) user_data;

    if (switch_mutex_trylock(tech_pvt->mutex) == SWITCH_STATUS_SUCCESS) {
      CircularBuffer_t *cBuffer = (CircularBuffer_t *) tech_pvt->playoutBuffer;

      // Do we need to interrupt the assistant?
      if (tech_pvt->process_interrupt) {
        tech_pvt->process_interrupt = false;
        cBuffer->clear();
        openai_s2s::AudioPipe *pAudioPipe = static_cast<openai_s2s::AudioPipe *>(tech_pvt->pAudioPipe);
        pAudioPipe->bufferForSending("{\"type\": \"response.cancel\"}");

        // Retrieve the session using the sessionId in tech_pvt
        switch_core_session_t *session = switch_core_session_locate(tech_pvt->sessionId);
        if (session) {
          // Send playout complete event due to interrupt
          tech_pvt->responseHandler(session, OAIS2S_EVENT_SERVER, 
            "{\"type\": \"output_audio.playback_stopped\", \"completion_reason\": \"interrupted\"}", tech_pvt->bugname);
          // Unlock the session after using it
          switch_core_session_rwunlock(session);
        }
      }

      if (cBuffer->size() > 0) {
        switch_frame_t* rframe = switch_core_media_bug_get_write_replace_frame(bug);
        int16_t *fp = reinterpret_cast<int16_t*>(rframe->data);

        rframe->channels = 1;
        rframe->datalen = rframe->samples * sizeof(int16_t);

        int16_t data[SWITCH_RECOMMENDED_BUFFER_SIZE];
        memset(data, 0, sizeof(data));
        int samplesToCopy = std::min(static_cast<int>(cBuffer->size()), static_cast<int>(rframe->samples));


        // copy the data and remove from the buffer
        std::copy_n(cBuffer->begin(), samplesToCopy, data);
        cBuffer->erase(cBuffer->begin(), cBuffer->begin() + samplesToCopy);

        if (cBuffer->size() == 0) {
          // send playout complete event due to completion
          tech_pvt->responseHandler(session, OAIS2S_EVENT_SERVER, 
            "{\"type\": \"output_audio.playback_stopped\": \"completion_reason\": \"completed\"}", tech_pvt->bugname);

        }

        if (samplesToCopy > 0) {
          vector_add(fp, data, rframe->samples);
           vector_normalize(fp, rframe->samples);
        }
         switch_core_media_bug_set_write_replace_frame(bug, rframe);
      }
      switch_mutex_unlock(tech_pvt->mutex);
    }

    return SWITCH_TRUE;
  }

	switch_bool_t openai_s2s_read_frame(switch_core_session_t *session, switch_media_bug_t *bug, void* user_data) {
    private_t* tech_pvt = (private_t*) user_data;
    size_t inuse = 0;
    bool dirty = false;
    char *p = (char *) "{\"msg\": \"buffer overrun\"}";

    if (!tech_pvt) return SWITCH_TRUE;

    /* dont send audio until initial response.created is received */
    if (tech_pvt->state != SESSION_STATE_CONVERSATION_STARTED) {
      return SWITCH_TRUE;
    }

    if (switch_mutex_trylock(tech_pvt->mutex) == SWITCH_STATUS_SUCCESS) {
      if (!tech_pvt->pAudioPipe) {
        switch_mutex_unlock(tech_pvt->mutex);
        return SWITCH_TRUE;
      }
      openai_s2s::AudioPipe *pAudioPipe = static_cast<openai_s2s::AudioPipe *>(tech_pvt->pAudioPipe);
      if (pAudioPipe->getLwsState() != openai_s2s::AudioPipe::LWS_CLIENT_CONNECTED) {
        switch_mutex_unlock(tech_pvt->mutex);
        return SWITCH_TRUE;
      }
      pAudioPipe->lockAudioBuffer();
      size_t available = pAudioPipe->binarySpaceAvailable();
      if (NULL == tech_pvt->resampler_in) {
        switch_frame_t frame = { 0 };
        frame.data = pAudioPipe->binaryWritePtr();
        frame.buflen = available;
        while (true) {

          // check if buffer would be overwritten; dump packets if so
          if (available < pAudioPipe->binaryMinSpace()) {
            if (!tech_pvt->buffer_overrun_notified) {
              tech_pvt->buffer_overrun_notified = 1;
              tech_pvt->responseHandler(session, OAIS2S_EVENT_BUFFER_OVERRUN, NULL, tech_pvt->bugname);
            }
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "(%u) dropping packets!\n", 
              tech_pvt->id);
            pAudioPipe->binaryWritePtrResetToZero();

            frame.data = pAudioPipe->binaryWritePtr();
            frame.buflen = available = pAudioPipe->binarySpaceAvailable();
          }

          switch_status_t rv = switch_core_media_bug_read(bug, &frame, SWITCH_TRUE);
          if (rv != SWITCH_STATUS_SUCCESS) break;
          if (frame.datalen) {
            pAudioPipe->binaryWritePtrAdd(frame.datalen);
            frame.buflen = available = pAudioPipe->binarySpaceAvailable();
            frame.data = pAudioPipe->binaryWritePtr();
            dirty = true;
          }
        }
      }
      else {
        uint8_t data[SWITCH_RECOMMENDED_BUFFER_SIZE];
        switch_frame_t frame = { 0 };
        frame.data = data;
        frame.buflen = SWITCH_RECOMMENDED_BUFFER_SIZE;
        while (switch_core_media_bug_read(bug, &frame, SWITCH_TRUE) == SWITCH_STATUS_SUCCESS) {
          if (frame.datalen) {
            spx_uint32_t out_len = available >> 1;  // space for samples which are 2 bytes
            spx_uint32_t in_len = frame.samples;

            speex_resampler_process_int(tech_pvt->resampler_in, 0,
              (const spx_int16_t *) frame.data, 
              (spx_uint32_t *) &in_len, 
              (spx_int16_t *) ((char *) pAudioPipe->binaryWritePtr()),
              &out_len);

            if (out_len > 0) {
              size_t bytes_written = out_len << 1;
              pAudioPipe->binaryWritePtrAdd(bytes_written);
              available = pAudioPipe->binarySpaceAvailable();
              dirty = true;
            }
            if (available < pAudioPipe->binaryMinSpace()) {
              if (!tech_pvt->buffer_overrun_notified) {
                tech_pvt->buffer_overrun_notified = 1;
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "(%u) dropping packets!\n", 
                  tech_pvt->id);
                tech_pvt->responseHandler(session, OAIS2S_EVENT_BUFFER_OVERRUN, NULL, tech_pvt->bugname);
              }
              break;
            }
          }
        }
      }

      pAudioPipe->unlockAudioBuffer();
      switch_mutex_unlock(tech_pvt->mutex);
    }
    return SWITCH_TRUE;
  }
}
