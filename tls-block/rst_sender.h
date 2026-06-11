#pragma once

#include "common.h"
#include "flow.h"

// ============================================================
// RST sender initialization
// ============================================================

bool set_rst_raw_socket(int raw_socket);


// ============================================================
// Flow termination with RST
// ============================================================

void terminate_flow_with_rst(const Flow_Key& key, ResetReason reason);


// ============================================================
// RST send functions
// ============================================================

bool send_bidirectional_rst(const Flow_Entry& flow, ResetReason reason);
bool send_forward_rst(const Flow_Entry& flow);
bool send_backward_rst(const Flow_Entry& flow);