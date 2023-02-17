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

// NOT FOR PRODUCTION

//paired header
#include "enote_store_mock_validator_v1.h"

//local headers
#include "common/container_helpers.h"
#include "enote_store_mock_v1.h"
#include "misc_log_ex.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/contextual_enote_record_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <ctime>
#include <functional>
#include <iterator>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockPaymentValidatorV1::get_received_sum(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t received_sum{0};

    for (const auto &mapped_contextual_record : m_sp_contextual_enote_records)
    {
        const SpContextualIntermediateEnoteRecordV1 &contextual_record{mapped_contextual_record.second};

        // ignore enotes with unrequested origins
        if (origin_statuses.find(contextual_record.m_origin_context.m_origin_status) == origin_statuses.end())
            continue;

        // ignore onchain enotes that are locked
        if (exclusions.find(EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            contextual_record.m_origin_context.m_origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_sp_enote_is_locked(
                    contextual_record.m_origin_context.m_block_index,
                    this->top_block_index(),
                    m_default_spendable_age
                ))
            continue;

        // update received sum
        received_sum += contextual_record.m_record.m_amount;
    }

    return received_sum;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockPaymentValidatorV1::try_get_block_id(const std::uint64_t block_index, rct::key &block_id_out) const
{
    if (block_index < m_refresh_index ||
        block_index > m_refresh_index + m_block_ids.size() - 1 ||
        m_block_ids.size() == 0)
        return false;

    block_id_out = m_block_ids[block_index - m_refresh_index];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockPaymentValidatorV1::update_with_sp_records_from_nonledger(
    const SpEnoteOriginStatus nonledger_origin_status,
    const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records)
{
    CHECK_AND_ASSERT_THROW_MES(nonledger_origin_status == SpEnoteOriginStatus::OFFCHAIN ||
            nonledger_origin_status == SpEnoteOriginStatus::UNCONFIRMED,
        "enote store mock v1 (clean maps for sp nonledger update): invalid origin status.");

    // 1. remove records that will be replaced
    tools::for_all_in_map_erase_if(m_sp_contextual_enote_records,
            [&](const auto &mapped_contextual_enote_record) -> bool
            {
                // remove all offchain enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status == nonledger_origin_status)
                    return true;

                return false;
            }
        );

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockPaymentValidatorV1::update_with_sp_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records,
    const std::vector<rct::key> &new_block_ids)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    CHECK_AND_ASSERT_THROW_MES(first_new_block >= m_refresh_index,
        "enote store ledger records update (mock): first new block is below the refresh index.");
    CHECK_AND_ASSERT_THROW_MES(first_new_block - m_refresh_index <= m_block_ids.size(),
        "enote store ledger records update (mock): new blocks don't line up with existing blocks.");
    if (first_new_block > m_refresh_index)
    {
        CHECK_AND_ASSERT_THROW_MES(alignment_block_id == m_block_ids[first_new_block - m_refresh_index - 1],
            "enote store ledger records update (mock): alignment block id doesn't align with recorded block ids.");
    }

    m_block_ids.resize(first_new_block - m_refresh_index);  //crop old blocks
    m_block_ids.insert(m_block_ids.end(), new_block_ids.begin(), new_block_ids.end());

    // 2. remove records that will be replaced
    tools::for_all_in_map_erase_if(m_sp_contextual_enote_records,
            [first_new_block](const auto &mapped_contextual_enote_record) -> bool
            {
                // a. remove onchain enotes in range [first_new_block, end of chain]
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::ONCHAIN &&
                    mapped_contextual_enote_record.second.m_origin_context.m_block_index >= first_new_block)
                {
                    return true;
                }

                // b. remove all unconfirmed enotes
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::UNCONFIRMED)
                    return true;

                return false;
            }
        );

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK PV ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockPaymentValidatorV1::add_record(const SpContextualIntermediateEnoteRecordV1 &new_record)
{
    const rct::key record_onetime_address{onetime_address_ref(new_record)};

    // add the record or update an existing record's origin context
    if (m_sp_contextual_enote_records.find(record_onetime_address) == m_sp_contextual_enote_records.end())
    {
        m_sp_contextual_enote_records[record_onetime_address] = new_record;
    }
    else
    {
        try_update_enote_origin_context_v1(new_record.m_origin_context,
            m_sp_contextual_enote_records[record_onetime_address].m_origin_context);
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp
