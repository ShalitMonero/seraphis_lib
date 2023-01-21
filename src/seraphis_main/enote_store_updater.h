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

// Dependency injectors for updating an enote storage with new enotes during balance recovery.

#pragma once

//local headers
#include "contextual_enote_record_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <list>
#include <unordered_map>
#include <vector>

//forward declarations


namespace sp
{

////
// EnoteStoreUpdater
// - provides an API for updating an enote store with chunks of enotes from find-received scanning
///
class EnoteStoreUpdater
{
public:
//destructor
    virtual ~EnoteStoreUpdater() = default;

//overloaded operators
    /// disable copy/move (this is an abstract base class)
    EnoteStoreUpdater& operator=(EnoteStoreUpdater&&) = delete;

//member functions
    /// try to get the recorded block id for a given height
    virtual bool try_get_block_id(const std::uint64_t block_height, rct::key &block_id_out) const = 0;
    /// get height of first block the internal enote store cares about
    virtual std::uint64_t refresh_height() const = 0;
    /// get height of first block the updater wants to have scanned
    virtual std::uint64_t desired_first_block() const = 0;

    /// consume a chunk of basic enote records and save the results
    virtual void consume_nonledger_chunk(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
        const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images) = 0;
    virtual void consume_onchain_chunk(
        const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
        const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
        const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids) = 0;
};

} //namespace sp
