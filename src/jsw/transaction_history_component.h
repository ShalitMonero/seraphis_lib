// Copyright (c) 2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Supporting types for Jamtis (address index, address tag hint, address tag, etc.).

#pragma once

// local headers

// third party headers

// standard headers
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "contextual_enote_record_types.h"
#include "enote_record_types.h"
#include "ringct/rctTypes.h"

// forward declarations

namespace jsw
{

struct transaction_out
{
    // General information about transaction
    rct::key txid;
    rct::xmr_amount fee;

    // Network data
    std::string status;  // Failed, Pending or Out(confirmed)
    uint64_t block_height;
    time_t sent_time;
    uint64_t timestamp;
    uint64_t unlock_time;

    // Enotes used as inputs
    std::vector<sp::SpContextualEnoteRecordV1> sp_enote_records;
    std::vector<sp::LegacyContextualEnoteRecordV1> legacy_enote_records;

    // Destination and ring members of the tx
    std::vector<std::pair<std::string, uint64_t>> dest_amount;               // destination and amount
    std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> rings;  // ring members
};

struct transaction_history_manager
{
    // a map may be better.
    // TODO: find fastest way to go from txid -> enotes
    std::vector<transaction_out> tx_history_manager;

    // Add methods to:
    // - get entries
    // - check duplicated entries
    // - update entries
    // - remove unnecessary entries
    // - optimzed queries, etc
};


}  // namespace jsw