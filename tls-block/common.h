#pragma once

#include <cstdio>
#include <cstdint>
#include <string>


// ============================================================
// Buffer / queue limits
// ============================================================

#define MAX_OOO_SEGMENTS             64
#define MAX_OOO_BYTES                (256 * 1024)

#define MAX_TLS_RECORD_BUFFER_SIZE   (64 * 1024)
#define MAX_TLS_RECORD_BODY_LENGTH   18432
#define MAX_TLS_RECORD_QUEUE_SIZE    24

#define FLOW_IDLE_TIMEOUT            30
#define FLOW_PROGRESS_TIMEOUT        30


// ============================================================
// Logging macros
// ============================================================

#define DEBUG_LOG(...)  do { std::fprintf(stderr, "[DEBUG] "); std::fprintf(stderr, __VA_ARGS__); std::fprintf(stderr, "\n"); } while(0)
#define INFO_LOG(...)   do { std::fprintf(stderr, "[INFO] ");  std::fprintf(stderr, __VA_ARGS__); std::fprintf(stderr, "\n"); } while(0)
#define ERROR_LOG(...)  do { std::fprintf(stderr, "[ERROR] "); std::fprintf(stderr, __VA_ARGS__); std::fprintf(stderr, "\n"); } while(0)


// ============================================================
// Reset reason
// ============================================================

enum class ResetReason
{
    BLOCKED_BY_SNI,
    BROKEN_FLOW
};


// ============================================================
// Global config
// ============================================================

extern std::string target_server_name;