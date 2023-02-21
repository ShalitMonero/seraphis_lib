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
#include "enote_store_mock_v1.h"

//local headers
#include "common/container_helpers.h"
#include "misc_log_ex.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/enote_record_utils_legacy.h"

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
//-------------------------------------------------------------------------------------------------------------------
static void update_block_ids_with_new_block_ids(const std::uint64_t first_allowed_index,
    const std::uint64_t first_new_block_index,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    std::vector<rct::key> &block_ids_inout,
    std::uint64_t &old_top_index_out,
    std::uint64_t &range_start_index_out,
    std::uint64_t &num_blocks_added_out)
{
    // 1. check inputs
    CHECK_AND_ASSERT_THROW_MES(first_new_block_index >= first_allowed_index,
        "enote store set new block ids (mock): first new block is below the refresh index.");
    CHECK_AND_ASSERT_THROW_MES(first_new_block_index - first_allowed_index <= block_ids_inout.size(),
        "enote store set new block ids (mock): new blocks don't line up with existing blocks.");
    if (first_new_block_index > first_allowed_index)
    {
        CHECK_AND_ASSERT_THROW_MES(alignment_block_id ==
                block_ids_inout[first_new_block_index - first_allowed_index - 1],
            "enote store set new block ids (mock): alignment block id doesn't align with recorded block ids.");
    }

    // 2. save the diff
    old_top_index_out     = first_allowed_index + block_ids_inout.size();
    range_start_index_out = first_new_block_index;
    num_blocks_added_out  = new_block_ids.size();

    // 3. update the block ids
    block_ids_inout.resize(first_new_block_index - first_allowed_index);  //crop old blocks
    block_ids_inout.insert(block_ids_inout.end(), new_block_ids.begin(), new_block_ids.end());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
SpEnoteStoreMockV1::SpEnoteStoreMockV1(const std::uint64_t refresh_index,
    const std::uint64_t first_sp_enabled_block_in_chain,
    const std::uint64_t default_spendable_age) :
        m_refresh_index{refresh_index},
        m_legacy_fullscan_index{refresh_index - 1},
        m_legacy_partialscan_index{refresh_index - 1},
        m_sp_scanned_index{refresh_index - 1},
        m_first_sp_enabled_block_in_chain{first_sp_enabled_block_in_chain},
        m_default_spendable_age{default_spendable_age}
{}
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockV1::get_balance(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t balance{0};

    // 1. intermediate legacy enotes (it is unknown if these enotes are spent)
    balance += this->get_balance_intermediate_legacy(origin_statuses, spent_statuses, exclusions);

    // 2. full legacy enotes
    balance += this->get_balance_full_legacy(origin_statuses, spent_statuses, exclusions);

    // 3. seraphis enotes
    balance += this->get_balance_seraphis(origin_statuses, spent_statuses, exclusions);

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t SpEnoteStoreMockV1::top_block_index() const
{
    // 1. no blocks
    if (m_legacy_block_ids.size() == 0 &&
        m_sp_block_ids.size() == 0)
        return m_refresh_index - 1;

    // 2. only have legacy blocks
    if (m_sp_block_ids.size() == 0)
        return m_refresh_index + m_legacy_block_ids.size() - 1;

    // 3. only have seraphis blocks
    if (m_legacy_block_ids.size() == 0)
        return this->sp_refresh_index() + m_sp_block_ids.size() - 1;

    // 4. have legacy and seraphis blocks
    return std::max(
            m_refresh_index + m_legacy_block_ids.size() - 1,
            this->sp_refresh_index() + m_sp_block_ids.size() - 1
        );
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_get_block_id_for_legacy_partialscan(const std::uint64_t block_index,
    rct::key &block_id_out) const
{
    // 1. check error states
    if (block_index < m_refresh_index ||
        block_index > m_refresh_index + m_legacy_block_ids.size() - 1 ||
        m_legacy_block_ids.size() == 0)
        return false;

    // 2. assume a block id is 'unknown' if its index is above the last legacy partial-scanned block index
    if (block_index + 1 > m_legacy_partialscan_index + 1)
        return false;

    // 3. get the block id
    block_id_out = m_legacy_block_ids[block_index - m_refresh_index];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_get_block_id_for_legacy_fullscan(const std::uint64_t block_index,
    rct::key &block_id_out) const
{
    // 1. check error states
    if (block_index < m_refresh_index ||
        block_index > m_refresh_index + m_legacy_block_ids.size() - 1 ||
        m_legacy_block_ids.size() == 0)
        return false;

    // 2. assume a block id is 'unknown' if its index is above the last legacy full-scanned block index
    if (block_index + 1 > m_legacy_fullscan_index + 1)
        return false;

    // 3. get the block id
    block_id_out = m_legacy_block_ids[block_index - m_refresh_index];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_get_block_id_for_sp(const std::uint64_t block_index, rct::key &block_id_out) const
{
    // 1. check error states
    if (block_index < this->sp_refresh_index() ||
        block_index > this->sp_refresh_index() + m_sp_block_ids.size() - 1 ||
        m_sp_block_ids.size() == 0)
        return false;

    // 2. assume a block id is 'unknown' if its index is above the last seraphis scanned block index
    if (block_index + 1 > m_sp_scanned_index + 1)
        return false;

    // 3. get the block id
    block_id_out = m_sp_block_ids[block_index - this->sp_refresh_index()];

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_get_block_id(const std::uint64_t block_index, rct::key &block_id_out) const
{
    // try to get the block id from each of the scan types
    return try_get_block_id_for_legacy_partialscan(block_index, block_id_out) ||
        try_get_block_id_for_legacy_fullscan(block_index, block_id_out) ||
        try_get_block_id_for_sp(block_index, block_id_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::has_enote_with_key_image(const crypto::key_image &key_image) const
{
    return m_sp_contextual_enote_records.find(key_image) != m_sp_contextual_enote_records.end() ||
        m_legacy_key_images.find(key_image) != m_legacy_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_get_legacy_enote_record(const crypto::key_image &key_image,
    LegacyContextualEnoteRecordV1 &contextual_record_out) const
{
    // drill into the legacy maps searching for at least one matching legacy enote record
    if (m_legacy_key_images.find(key_image) == m_legacy_key_images.end())
        return false;

    const rct::key &onetime_address{m_legacy_key_images.at(key_image)};

    if (m_tracked_legacy_onetime_address_duplicates.find(onetime_address) ==
            m_tracked_legacy_onetime_address_duplicates.end())
        return false;

    const std::unordered_set<rct::key> &identifiers_of_duplicates{
            m_tracked_legacy_onetime_address_duplicates.at(onetime_address)
        };

    if (identifiers_of_duplicates.size() == 0)
        return false;

    // search for the highest-amount enote amoung the duplicates
    rct::key best_identifier{rct::zero()};
    rct::xmr_amount best_amount{0};
    rct::xmr_amount temp_record_amount;

    for (const rct::key &identifier : identifiers_of_duplicates)
    {
        if (m_legacy_intermediate_contextual_enote_records.find(identifier) !=
            m_legacy_intermediate_contextual_enote_records.end())
        {
            temp_record_amount = m_legacy_intermediate_contextual_enote_records.at(identifier).m_record.m_amount;
        }
        else if (m_legacy_contextual_enote_records.find(identifier) !=
            m_legacy_contextual_enote_records.end())
        {
            temp_record_amount = m_legacy_contextual_enote_records.at(identifier).m_record.m_amount;
        }
        else
            continue;

        if (best_amount < temp_record_amount)
        {
            best_identifier = identifier;
            best_amount = temp_record_amount;
        }
    }

    // if the highest-amount enote is not amoung the full enote records, then we failed
    if (m_legacy_contextual_enote_records.find(best_identifier) == m_legacy_contextual_enote_records.end())
        return false;

    contextual_record_out = m_legacy_contextual_enote_records.at(best_identifier);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_get_sp_enote_record(const crypto::key_image &key_image,
    SpContextualEnoteRecordV1 &contextual_record_out) const
{
    if (m_sp_contextual_enote_records.find(key_image) == m_sp_contextual_enote_records.end())
        return false;

    contextual_record_out = m_sp_contextual_enote_records.at(key_image);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpEnoteStoreMockV1::try_import_legacy_key_image(const crypto::key_image &legacy_key_image,
    const rct::key &onetime_address,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. we are done if there are no enote records for this onetime address
    if (m_tracked_legacy_onetime_address_duplicates.find(onetime_address) ==
        m_tracked_legacy_onetime_address_duplicates.end())
        return false;

    // 2. if this key image appeared in a seraphis tx, get the spent context
    SpEnoteSpentContextV1 spent_context{};

    if (m_legacy_key_images_in_sp_selfsends.find(legacy_key_image) != m_legacy_key_images_in_sp_selfsends.end())
        spent_context = m_legacy_key_images_in_sp_selfsends.at(legacy_key_image);

    // 3. there may be full legacy enote records with this key image, use them to update the spent context
    for (const rct::key &legacy_enote_identifier : m_tracked_legacy_onetime_address_duplicates[onetime_address])
    {
        // a. skip identifiers not in the full legacy records map
        if (m_legacy_contextual_enote_records.find(legacy_enote_identifier) ==
            m_legacy_contextual_enote_records.end())
            continue;

        // b. update the spent context
        if (try_update_enote_spent_context_v1(
                m_legacy_contextual_enote_records.at(legacy_enote_identifier).m_spent_context,
                spent_context))
            changes_inout.emplace_back(UpdatedLegacySpentContext{legacy_enote_identifier});
    }

    // 4. promote intermediate enote records with this onetime address to full enote records
    for (const rct::key &legacy_enote_identifier : m_tracked_legacy_onetime_address_duplicates[onetime_address])
    {
        // a. skip identifiers not in the intermediate records map
        if (m_legacy_intermediate_contextual_enote_records.find(legacy_enote_identifier) ==
            m_legacy_intermediate_contextual_enote_records.end())
            continue;

        // b. if this identifier has an intermediate record, it should not have a full record
        CHECK_AND_ASSERT_THROW_MES(m_legacy_contextual_enote_records.find(legacy_enote_identifier) ==
                m_legacy_contextual_enote_records.end(),
            "import legacy key image (enote store mock): intermediate and full legacy maps inconsistent (bug).");

        // c. set the full record
        get_legacy_enote_record(
            m_legacy_intermediate_contextual_enote_records[legacy_enote_identifier].m_record,
            legacy_key_image,
            m_legacy_contextual_enote_records[legacy_enote_identifier].m_record);
        changes_inout.emplace_back(NewLegacyRecord{legacy_enote_identifier});

        // d. set the full record's contexts
        update_contextual_enote_record_contexts_v1(
                m_legacy_intermediate_contextual_enote_records[legacy_enote_identifier].m_origin_context,
                spent_context,
                m_legacy_contextual_enote_records[legacy_enote_identifier].m_origin_context,
                m_legacy_contextual_enote_records[legacy_enote_identifier].m_spent_context
            );

        // e. remove the intermediate record
        m_legacy_intermediate_contextual_enote_records.erase(legacy_enote_identifier);
        changes_inout.emplace_back(RemovedLegacyIntermediateRecord{legacy_enote_identifier});

        // f. save to the legacy key image set
        m_legacy_key_images[legacy_key_image] = onetime_address;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_legacy_fullscan_index_for_import_cycle(const std::uint64_t saved_index)
{
    // clamp the imported index to the top known block index in case blocks were popped in the middle of an import
    //   cycle and the enote store was refreshed before this function call
    this->set_last_legacy_fullscan_index(std::min(saved_index + 1, m_refresh_index + m_legacy_block_ids.size()) - 1);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::set_last_legacy_fullscan_index(const std::uint64_t new_index)
{
    // 1. set this scan index (+1 because if no scanning has been done then we are below the refresh index)
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 >= m_refresh_index,
        "mock enote store (set legacy fullscan index): new index is below refresh index.");
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 <= m_refresh_index + m_legacy_block_ids.size(),
        "mock enote store (set legacy fullscan index): new index is above known block range.");

    m_legacy_fullscan_index = new_index;

    // 2. update legacy partial scan index
    // - fullscan qualifies as partialscan
    // note: this update intentionally won't fix inaccuracy in the m_legacy_partialscan_index caused by a reorg, because
    //       in manual workflows the legacy partialscan index is often higher than the legacy fullscan index; the
    //       partialscan index only matters when doing a manual view-only workflow, and any reorg-induced inaccuracy
    //       in that height will be fixed by re-running that workflow
    m_legacy_partialscan_index = std::max(m_legacy_partialscan_index + 1, m_legacy_fullscan_index + 1) - 1;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::set_last_legacy_partialscan_index(const std::uint64_t new_index)
{
    // 1. set this scan index
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 >= m_refresh_index,
        "mock enote store (set legacy partialscan index): new index is below refresh index.");
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 <= m_refresh_index + m_legacy_block_ids.size(),
        "mock enote store (set legacy partialscan index): new index is above known block range.");

    m_legacy_partialscan_index = new_index;

    // 2. update legacy full scan index
    // - if partialscan index is below fullscan index, assume this means there was a reorg
    m_legacy_fullscan_index = std::min(m_legacy_fullscan_index + 1, m_legacy_partialscan_index + 1) - 1;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::set_last_sp_scanned_index(const std::uint64_t new_index)
{
    // set this scan index
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 >= this->sp_refresh_index(),
        "mock enote store (set seraphis scan index): new index is below refresh index.");
    CHECK_AND_ASSERT_THROW_MES(new_index + 1 <= this->sp_refresh_index() + m_sp_block_ids.size(),
        "mock enote store (set seraphis scan index): new index is above known block range.");

    m_sp_scanned_index = new_index;
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_intermediate_legacy_records_from_nonledger(
    const SpEnoteOriginStatus nonledger_origin_status,
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_nonledger_update(nonledger_origin_status, found_spent_key_images, changes_inout);

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, changes_inout);

    // 3. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_intermediate_legacy_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. update block tracking info
    this->update_with_new_blocks_from_ledger_legacy_intermediate(first_new_block,
        alignment_block_id,
        new_block_ids,
        changes_inout);

    // 2. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_ledger_update(first_new_block, found_spent_key_images, changes_inout);

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, changes_inout);

    // 4. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_intermediate_legacy_found_spent_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. clean up enote store maps that conflict with the found spent key images (which take precedence)
    this->clean_maps_for_found_spent_legacy_key_images(found_spent_key_images, changes_inout);

    // 2. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_legacy_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_nonledger_update(nonledger_origin_status, found_spent_key_images, changes_inout);

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, changes_inout);

    // 3. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_legacy_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. update block tracking info
    this->update_with_new_blocks_from_ledger_legacy_full(first_new_block,
        alignment_block_id,
        new_block_ids,
        changes_inout);

    // 2. clean up enote store maps in preparation for adding fresh enotes and key images
    this->clean_maps_for_legacy_ledger_update(first_new_block, found_spent_key_images, changes_inout);

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, changes_inout);

    // 4. update contexts of stored enotes with found spent key images
    this->update_legacy_with_fresh_found_spent_key_images(found_spent_key_images, changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_sp_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status, 
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. remove records that will be replaced
    this->clean_maps_for_sp_nonledger_update(nonledger_origin_status, changes_inout);

    // 2. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, changes_inout);

    // 3. update spent contexts of stored enotes with found spent key images
    this->update_sp_with_fresh_found_spent_key_images(found_spent_key_images, changes_inout);

    // 4. handle legacy key images attached to self-spends
    this->handle_legacy_key_images_from_sp_selfsends(legacy_key_images_in_sp_selfsends, changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_sp_records_from_ledger(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. update block tracking info
    this->update_with_new_blocks_from_ledger_sp(first_new_block, alignment_block_id, new_block_ids, changes_inout);

    // 2. remove records that will be replaced
    this->clean_maps_for_sp_ledger_update(first_new_block, changes_inout);

    // 3. add found enotes
    for (const auto &found_enote_record : found_enote_records)
        this->add_record(found_enote_record.second, changes_inout);

    // 4. update contexts of stored enotes with found spent key images
    this->update_sp_with_fresh_found_spent_key_images(found_spent_key_images, changes_inout);

    // 5. handle legacy key images attached to self-spends (this should be a subset of found_spent_key_images)
    this->handle_legacy_key_images_from_sp_selfsends(legacy_key_images_in_sp_selfsends, changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockV1::get_balance_intermediate_legacy(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t balance{0};

    // 1. ignore if requested
    if (exclusions.find(EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE) != exclusions.end())
        return 0;

    // 2. accumulate balance
    // note: it is unknown if enotes in intermediate records are spent
    for (const auto &mapped_contextual_record : m_legacy_intermediate_contextual_enote_records)
    {
        const LegacyContextualIntermediateEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. only include this enote if its origin status is requested
        if (origin_statuses.find(current_contextual_record.m_origin_context.m_origin_status) == origin_statuses.end())
            continue;

        // b. ignore onchain enotes that are locked
        if (exclusions.find(EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.m_origin_context.m_origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_legacy_enote_is_locked(
                    current_contextual_record.m_origin_context.m_block_index,
                    current_contextual_record.m_record.m_unlock_time,
                    this->top_block_index(),
                    m_default_spendable_age,
                    static_cast<std::uint64_t>(std::time(nullptr)))
                )
            continue;

        // c. ignore enotes that share onetime addresses with other enotes but don't have the highest amount among them
        CHECK_AND_ASSERT_THROW_MES(m_tracked_legacy_onetime_address_duplicates
                    .find(onetime_address_ref(current_contextual_record.m_record.m_enote)) !=
                m_tracked_legacy_onetime_address_duplicates.end(),
            "enote store balance check (mock): tracked legacy duplicates is missing a onetime address (bug).");

        if (!legacy_enote_has_highest_amount_in_set(mapped_contextual_record.first,
                current_contextual_record.m_record.m_amount,
                origin_statuses,
                m_tracked_legacy_onetime_address_duplicates.at(
                    onetime_address_ref(current_contextual_record.m_record.m_enote)
                ),
                [this](const rct::key &identifier) -> const SpEnoteOriginStatus&
                {
                    CHECK_AND_ASSERT_THROW_MES(m_legacy_intermediate_contextual_enote_records.find(
                            identifier) != m_legacy_intermediate_contextual_enote_records.end(),
                        "enote store balance check (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy intermediate map even though it should (bug).");

                    return m_legacy_intermediate_contextual_enote_records
                        .at(identifier)
                        .m_origin_context
                        .m_origin_status;
                },
                [this](const rct::key &identifier) -> rct::xmr_amount
                {
                    CHECK_AND_ASSERT_THROW_MES(m_legacy_intermediate_contextual_enote_records.find(
                            identifier) != m_legacy_intermediate_contextual_enote_records.end(),
                        "enote store balance check (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy intermediate map even though it should (bug).");

                    return m_legacy_intermediate_contextual_enote_records.at(identifier).m_record.m_amount;
                }))
            continue;

        // d. update balance
        balance += current_contextual_record.m_record.m_amount;
    }

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockV1::get_balance_full_legacy(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t balance{0};

    // 1. ignore if requested
    if (exclusions.find(EnoteStoreBalanceUpdateExclusions::LEGACY_FULL) != exclusions.end())
        return 0;

    // 2. accumulate balance
    for (const auto &mapped_contextual_record : m_legacy_contextual_enote_records)
    {
        const LegacyContextualEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. only include this enote if its origin status is requested
        if (origin_statuses.find(current_contextual_record.m_origin_context.m_origin_status) == origin_statuses.end())
            continue;

        // b. if the enote's spent status is requested, then DON'T include this enote
        if (spent_statuses.find(current_contextual_record.m_spent_context.m_spent_status) != spent_statuses.end())
            continue;

        // c. ignore onchain enotes that are locked
        if (exclusions.find(EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.m_origin_context.m_origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_legacy_enote_is_locked(
                    current_contextual_record.m_origin_context.m_block_index,
                    current_contextual_record.m_record.m_unlock_time,
                    this->top_block_index(),
                    m_default_spendable_age,
                    static_cast<std::uint64_t>(std::time(nullptr)))
                )
            continue;

        // d. ignore enotes that share onetime addresses with other enotes but don't have the highest amount among them
        CHECK_AND_ASSERT_THROW_MES(m_tracked_legacy_onetime_address_duplicates
                    .find(onetime_address_ref(current_contextual_record.m_record.m_enote)) !=
                m_tracked_legacy_onetime_address_duplicates.end(),
            "enote store balance check (mock): tracked legacy duplicates is missing a onetime address (bug).");

        if (!legacy_enote_has_highest_amount_in_set(mapped_contextual_record.first,
                current_contextual_record.m_record.m_amount,
                origin_statuses,
                m_tracked_legacy_onetime_address_duplicates.at(
                    onetime_address_ref(current_contextual_record.m_record.m_enote)
                ),
                [this](const rct::key &identifier) -> const SpEnoteOriginStatus&
                {
                    CHECK_AND_ASSERT_THROW_MES(m_legacy_contextual_enote_records.find(identifier) !=
                            m_legacy_contextual_enote_records.end(),
                        "enote store balance check (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return m_legacy_contextual_enote_records
                        .at(identifier)
                        .m_origin_context
                        .m_origin_status;
                },
                [this](const rct::key &identifier) -> rct::xmr_amount
                {
                    CHECK_AND_ASSERT_THROW_MES(m_legacy_contextual_enote_records.find(identifier) != 
                            m_legacy_contextual_enote_records.end(),
                        "enote store balance check (mock): tracked legacy duplicates has an entry that doesn't line up "
                        "1:1 with the legacy map even though it should (bug).");

                    return m_legacy_contextual_enote_records.at(identifier).m_record.m_amount;
                }))
            continue;

        // e. update balance
        balance += current_contextual_record.m_record.m_amount;
    }

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
boost::multiprecision::uint128_t SpEnoteStoreMockV1::get_balance_seraphis(
    const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
    const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
    const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const
{
    boost::multiprecision::uint128_t balance{0};

    // 1. ignore if requested
    if (exclusions.find(EnoteStoreBalanceUpdateExclusions::SERAPHIS) != exclusions.end())
        return 0;

    // 2. accumulate balance
    for (const auto &mapped_contextual_record : m_sp_contextual_enote_records)
    {
        const SpContextualEnoteRecordV1 &current_contextual_record{mapped_contextual_record.second};

        // a. only include this enote if its origin status is requested
        if (origin_statuses.find(current_contextual_record.m_origin_context.m_origin_status) == origin_statuses.end())
            continue;

        // b. if the enote's spent status is requested, then DON'T include this enote
        if (spent_statuses.find(current_contextual_record.m_spent_context.m_spent_status) != spent_statuses.end())
            continue;

        // c. ignore onchain enotes that are locked
        if (exclusions.find(EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED) != exclusions.end() &&
            current_contextual_record.m_origin_context.m_origin_status == SpEnoteOriginStatus::ONCHAIN &&
            onchain_sp_enote_is_locked(
                    current_contextual_record.m_origin_context.m_block_index,
                    this->top_block_index(),
                    m_default_spendable_age
                ))
            continue;

        // d. update balance
        balance += current_contextual_record.m_record.m_amount;
    }

    return balance;
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_new_blocks_from_ledger_legacy_intermediate(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    LegacyIntermediateBlocksDiff diff{};
    update_block_ids_with_new_block_ids(m_refresh_index,
        first_new_block,
        alignment_block_id,
        new_block_ids,
        m_legacy_block_ids,
        diff.old_top_index,
        diff.range_start_index,
        diff.num_blocks_added);
    changes_inout.emplace_back(diff);

    // 2. update scanning index for this scan mode (assumed to be LEGACY_INTERMEDIATE_FULL)
    this->set_last_legacy_partialscan_index(first_new_block + new_block_ids.size() - 1);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_new_blocks_from_ledger_legacy_full(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    LegacyBlocksDiff diff{};
    update_block_ids_with_new_block_ids(m_refresh_index,
        first_new_block,
        alignment_block_id,
        new_block_ids,
        m_legacy_block_ids,
        diff.old_top_index,
        diff.range_start_index,
        diff.num_blocks_added);
    changes_inout.emplace_back(diff);

    // 2. update scanning index for this scan mode (assumed to be LEGACY_FULL)
    // note: we must set the partialscan index here in case a reorg dropped blocks; we don't do it inside the
    //       set_last_legacy_fullscan_index() function because it needs to be used a manual view-scanning workflows
    //       where the legacy fullscan index will often lag behind the partialscan index
    this->set_last_legacy_partialscan_index(first_new_block + new_block_ids.size() - 1);
    this->set_last_legacy_fullscan_index(first_new_block + new_block_ids.size() - 1);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_with_new_blocks_from_ledger_sp(const std::uint64_t first_new_block,
    const rct::key &alignment_block_id,
    const std::vector<rct::key> &new_block_ids,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. set new block ids in range [first_new_block, end of chain]
    SpBlocksDiff diff{};
    update_block_ids_with_new_block_ids(this->sp_refresh_index(),
        first_new_block,
        alignment_block_id,
        new_block_ids,
        m_sp_block_ids,
        diff.old_top_index,
        diff.range_start_index,
        diff.num_blocks_added);
    changes_inout.emplace_back(diff);

    // 2. update scanning index for this scan mode (assumed to be SERAPHIS)
    this->set_last_sp_scanned_index(first_new_block + new_block_ids.size() - 1);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_found_spent_legacy_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. if a found legacy key image is in the 'legacy key images from sp txs' map, remove it from that map
    // - a fresh spent context for legacy key images implies seraphis txs were reorged; we want to guarantee that the
    //   fresh spent contexts are applied to our stored enotes, and doing this step achieves that
    // - save the key images removed so we can clear the corresponding spent contexts in the enote records
    std::unordered_map<crypto::key_image, rct::key> spent_contexts_removed_from_sp_selfsends;
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        if (m_legacy_key_images_in_sp_selfsends.find(found_spent_key_image.first) ==
            m_legacy_key_images_in_sp_selfsends.end())
            continue;

        spent_contexts_removed_from_sp_selfsends[found_spent_key_image.first] =
            m_legacy_key_images_in_sp_selfsends.at(found_spent_key_image.first).m_transaction_id;

        m_legacy_key_images_in_sp_selfsends.erase(found_spent_key_image.first);
    }

    // 2. clear spent contexts referencing legacy key images removed from the seraphis legacy key image tracker
    for (auto &mapped_contextual_enote_record : m_legacy_contextual_enote_records)
    {
        // ignore legacy key images found in seraphis txs that still exist
        if (m_legacy_key_images_in_sp_selfsends.find(mapped_contextual_enote_record.second.m_record.m_key_image) !=
                m_legacy_key_images_in_sp_selfsends.end())
            continue;

        // clear spent contexts of key images removed from the seraphis selfsends tracker if the entries removed from the
        //   tracker have the same transaction id (i.e. the spent context recorded next to the key image corresponds with
        //   the removed tracker)
        if (spent_contexts_removed_from_sp_selfsends.find(mapped_contextual_enote_record.second.m_record.m_key_image) !=
                spent_contexts_removed_from_sp_selfsends.end() &&
            spent_contexts_removed_from_sp_selfsends.at(mapped_contextual_enote_record.second.m_record.m_key_image) ==
                mapped_contextual_enote_record.second.m_spent_context.m_transaction_id)
        {
            mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
            changes_inout.emplace_back(ClearedLegacySpentContext{mapped_contextual_enote_record.first});
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_removed_legacy_enotes(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    const std::unordered_map<rct::key, std::unordered_set<rct::key>> &mapped_identifiers_of_removed_enotes,
    const std::unordered_map<rct::key, crypto::key_image> &mapped_key_images_of_removed_enotes,
    const std::function<bool(const SpEnoteSpentContextV1&)> &spent_context_clearable_func,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. clean maps that conflict with the found spent key images
    this->clean_maps_for_found_spent_legacy_key_images(found_spent_key_images, changes_inout);

    // 2. clear spent contexts referencing removed blocks or the unconfirmed cache if the corresponding legacy key image
    //    is not in the seraphis legacy key image tracker
    for (auto &mapped_contextual_enote_record : m_legacy_contextual_enote_records)
    {
        // ignore legacy key images found in seraphis txs that still exist
        if (m_legacy_key_images_in_sp_selfsends.find(mapped_contextual_enote_record.second.m_record.m_key_image) !=
                m_legacy_key_images_in_sp_selfsends.end())
            continue;

        // ignore spent contexts that aren't clearable according to the caller
        if (!spent_context_clearable_func(mapped_contextual_enote_record.second.m_spent_context))
            continue;

        // clear spent contexts that point to txs that the enote store considers nonexistent
        mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
        changes_inout.emplace_back(ClearedLegacySpentContext{mapped_contextual_enote_record.first});
    }

    // 3. clean up legacy trackers
    // a. onetime address duplicate tracker: remove identifiers of removed txs
    for (const auto &mapped_identifiers : mapped_identifiers_of_removed_enotes)
    {
        if (m_tracked_legacy_onetime_address_duplicates.find(mapped_identifiers.first) ==
            m_tracked_legacy_onetime_address_duplicates.end())
            continue;

        for (const rct::key &identifier_of_removed_enote : mapped_identifiers.second)
        {
            m_tracked_legacy_onetime_address_duplicates[mapped_identifiers.first].erase(identifier_of_removed_enote);
        }

        if (m_tracked_legacy_onetime_address_duplicates[mapped_identifiers.first].size() == 0)
            m_tracked_legacy_onetime_address_duplicates.erase(mapped_identifiers.first);
    }

    // b. legacy key image tracker: remove any key images of removed txs if the corresponding onetime addresses don't
    //    have any identifiers registered in the duplicate tracker
    for (const auto &mapped_key_image : mapped_key_images_of_removed_enotes)
    {
        if (m_tracked_legacy_onetime_address_duplicates.find(mapped_key_image.first) == 
            m_tracked_legacy_onetime_address_duplicates.end())
        {
            m_legacy_key_images.erase(mapped_key_image.second);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_legacy_nonledger_update(const SpEnoteOriginStatus nonledger_origin_status,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    CHECK_AND_ASSERT_THROW_MES(nonledger_origin_status == SpEnoteOriginStatus::OFFCHAIN ||
            nonledger_origin_status == SpEnoteOriginStatus::UNCONFIRMED,
        "enote store mock v1 (clean maps for sp nonledger update): invalid origin status.");

    // 1. remove records that will be replaced
    std::unordered_map<rct::key, std::unordered_set<rct::key>> mapped_identifiers_of_removed_enotes;

    auto legacy_contextual_record_is_removable_func =
        [&](const auto &mapped_contextual_enote_record) -> bool
        {
            // ignore enotes of unspecified origin
            if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status != nonledger_origin_status)
                return false;

            mapped_identifiers_of_removed_enotes[
                    onetime_address_ref(mapped_contextual_enote_record.second.m_record.m_enote)
                ].insert(mapped_contextual_enote_record.first);

            return true;
        };

    // a. legacy intermediate records
    tools::for_all_in_map_erase_if(m_legacy_intermediate_contextual_enote_records,
            [&](const auto &mapped_contextual_enote_record) -> bool
            {
                // a. check if the record is removable
                if (!legacy_contextual_record_is_removable_func(mapped_contextual_enote_record))
                    return false;

                // b. record the identifier of the record being removed
                changes_inout.emplace_back(RemovedLegacyIntermediateRecord{mapped_contextual_enote_record.first});

                // c. remove the record
                return true;
            }
        );

    // b. legacy full records
    std::unordered_map<rct::key, crypto::key_image> mapped_key_images_of_removed_enotes;  //mapped to onetime address

    tools::for_all_in_map_erase_if(m_legacy_contextual_enote_records,
            [&](const auto &mapped_contextual_enote_record) -> bool
            {
                // a. check if the record is removable
                if (!legacy_contextual_record_is_removable_func(mapped_contextual_enote_record))
                    return false;

                // b. save key images of full records that are to be removed
                mapped_key_images_of_removed_enotes[
                        onetime_address_ref(mapped_contextual_enote_record.second.m_record.m_enote)
                    ] = mapped_contextual_enote_record.second.m_record.m_key_image;

                // c. record the identifier of the record being removed
                changes_inout.emplace_back(RemovedLegacyRecord{mapped_contextual_enote_record.first});

                // d. remove the record
                return true;
            }
        );

    // 2. clean maps for removed enotes
    // - set the spent context test function to the nonledger type, which means any spent contexts of that type
    //   can be cleared because the nonledger update involves clearing and replacing txs in that category
    this->clean_maps_for_removed_legacy_enotes(found_spent_key_images,
        mapped_identifiers_of_removed_enotes,
        mapped_key_images_of_removed_enotes,
        [nonledger_origin_status](const SpEnoteSpentContextV1 &spent_context) -> bool
        {
            // offchain check
            if (nonledger_origin_status == SpEnoteOriginStatus::OFFCHAIN &&
                spent_context.m_spent_status == SpEnoteSpentStatus::SPENT_OFFCHAIN)
                return true;

            // unconfirmed check
            if (nonledger_origin_status == SpEnoteOriginStatus::UNCONFIRMED &&
                spent_context.m_spent_status == SpEnoteSpentStatus::SPENT_UNCONFIRMED)
                return true;

            return false;
        },
        changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_legacy_ledger_update(const std::uint64_t first_new_block,
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. remove records that will be replaced
    std::unordered_map<rct::key, std::unordered_set<rct::key>> mapped_identifiers_of_removed_enotes;

    auto legacy_contextual_record_is_removable_func =
        [&](const auto &mapped_contextual_enote_record) -> bool
        {
            // remove onchain enotes in range [first_new_block, end of chain]
            if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                    SpEnoteOriginStatus::ONCHAIN &&
                mapped_contextual_enote_record.second.m_origin_context.m_block_index >= first_new_block)
            {
                mapped_identifiers_of_removed_enotes[
                        onetime_address_ref(mapped_contextual_enote_record.second.m_record.m_enote)
                    ].insert(mapped_contextual_enote_record.first);

                return true;
            }

            return false;
        };

    // a. legacy intermediate records
    tools::for_all_in_map_erase_if(m_legacy_intermediate_contextual_enote_records,
            [&](const auto &mapped_contextual_enote_record) -> bool
            {
                // a. check if the record is removable
                if (!legacy_contextual_record_is_removable_func(mapped_contextual_enote_record))
                    return false;

                // b. record the identifier of the record being removed
                changes_inout.emplace_back(RemovedLegacyIntermediateRecord{mapped_contextual_enote_record.first});

                // c. remove the record
                return true;
            }
        );

    // b. legacy full records
    std::unordered_map<rct::key, crypto::key_image> mapped_key_images_of_removed_enotes;  //mapped to onetime address

    tools::for_all_in_map_erase_if(m_legacy_contextual_enote_records,
            [&](const auto &mapped_contextual_enote_record) -> bool
            {
                // a. check if the record is removable
                if (!legacy_contextual_record_is_removable_func(mapped_contextual_enote_record))
                    return false;

                // b. save key images of full records that are to be removed
                mapped_key_images_of_removed_enotes[
                        onetime_address_ref(mapped_contextual_enote_record.second.m_record.m_enote)
                    ] = mapped_contextual_enote_record.second.m_record.m_key_image;

                // c. record the identifier of the record being removed
                changes_inout.emplace_back(RemovedLegacyRecord{mapped_contextual_enote_record.first});

                // d. remove the record
                return true;
            }
        );

    // 2. clean maps for removed enotes
    // - set the spent context test function to check if the context points to a tx in the removed/replaced blocks
    this->clean_maps_for_removed_legacy_enotes(found_spent_key_images,
        mapped_identifiers_of_removed_enotes,
        mapped_key_images_of_removed_enotes,
        [first_new_block](const SpEnoteSpentContextV1 &spent_context) -> bool
        {
            return spent_context.m_spent_status == SpEnoteSpentStatus::SPENT_ONCHAIN &&
                spent_context.m_block_index >= first_new_block;
        },
        changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_removed_sp_enotes(const std::unordered_set<rct::key> &tx_ids_of_removed_enotes,
    std::list<EnoteStoreChange> &changes_inout)
{
    // clear spent contexts referencing the txs of removed enotes (key images only appear at the same time as selfsends)

    // 1. seraphis enotes
    for (auto &mapped_contextual_enote_record : m_sp_contextual_enote_records)
    {
        if (tx_ids_of_removed_enotes.find(mapped_contextual_enote_record.second.m_spent_context.m_transaction_id) ==
                tx_ids_of_removed_enotes.end())
            continue;

        mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
        changes_inout.emplace_back(ClearedSpSpentContext{mapped_contextual_enote_record.first});
    }

    // 2. legacy enotes
    for (auto &mapped_contextual_enote_record : m_legacy_contextual_enote_records)
    {
        if (tx_ids_of_removed_enotes.find(mapped_contextual_enote_record.second.m_spent_context.m_transaction_id) ==
                tx_ids_of_removed_enotes.end())
            continue;

        mapped_contextual_enote_record.second.m_spent_context = SpEnoteSpentContextV1{};
        changes_inout.emplace_back(ClearedLegacySpentContext{mapped_contextual_enote_record.first});
    }

    // 3. remove legacy key images found in removed txs
    tools::for_all_in_map_erase_if(m_legacy_key_images_in_sp_selfsends,
            [&tx_ids_of_removed_enotes](const auto &mapped_legacy_key_images) -> bool
            {
                return tx_ids_of_removed_enotes.find(mapped_legacy_key_images.second.m_transaction_id) !=
                    tx_ids_of_removed_enotes.end();
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_sp_nonledger_update(const SpEnoteOriginStatus nonledger_origin_status,
    std::list<EnoteStoreChange> &changes_inout)
{
    CHECK_AND_ASSERT_THROW_MES(nonledger_origin_status == SpEnoteOriginStatus::OFFCHAIN ||
            nonledger_origin_status == SpEnoteOriginStatus::UNCONFIRMED,
        "enote store mock v1 (clean maps for sp nonledger update): invalid origin status.");

    // 1. remove records
    std::unordered_set<rct::key> tx_ids_of_removed_enotes;  //note: only txs with selfsends are needed in practice

    tools::for_all_in_map_erase_if(m_sp_contextual_enote_records,
            [&](const auto &mapped_contextual_enote_record) -> bool
            {
                // ignore enotes that don't have our specified origin status
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status != nonledger_origin_status)
                    return false;

                tx_ids_of_removed_enotes.insert(
                        mapped_contextual_enote_record.second.m_origin_context.m_transaction_id
                    );

                changes_inout.emplace_back(RemovedSpRecord{mapped_contextual_enote_record.first});

                return true;
            }
        );

    // 2. clean maps for removed enotes
    this->clean_maps_for_removed_sp_enotes(tx_ids_of_removed_enotes, changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::clean_maps_for_sp_ledger_update(const std::uint64_t first_new_block,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. remove records
    std::unordered_set<rct::key> tx_ids_of_removed_enotes;  //note: only txs with selfsends are needed in practice

    tools::for_all_in_map_erase_if(m_sp_contextual_enote_records,
            [&](const auto &mapped_contextual_enote_record) -> bool
            {
                // remove onchain enotes in range [first_new_block, end of chain]
                if (mapped_contextual_enote_record.second.m_origin_context.m_origin_status ==
                        SpEnoteOriginStatus::ONCHAIN &&
                    mapped_contextual_enote_record.second.m_origin_context.m_block_index >= first_new_block)
                {
                    tx_ids_of_removed_enotes.insert(
                            mapped_contextual_enote_record.second.m_origin_context.m_transaction_id
                        );
                    changes_inout.emplace_back(RemovedSpRecord{mapped_contextual_enote_record.first});
                    return true;
                }

                return false;
            }
        );

    // 2. clean maps for removed enotes
    this->clean_maps_for_removed_sp_enotes(tx_ids_of_removed_enotes, changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::add_record(const LegacyContextualIntermediateEnoteRecordV1 &new_record,
    std::list<EnoteStoreChange> &changes_inout)
{
    // 1. if key image is known, promote to a full enote record
    if (m_tracked_legacy_onetime_address_duplicates.find(onetime_address_ref(new_record.m_record.m_enote)) !=
        m_tracked_legacy_onetime_address_duplicates.end())
    {
        const auto &identifiers_of_known_enotes =
            m_tracked_legacy_onetime_address_duplicates.at(onetime_address_ref(new_record.m_record.m_enote));

        CHECK_AND_ASSERT_THROW_MES(identifiers_of_known_enotes.size() > 0,
            "add intermediate record (mock enote store): record's onetime address is known, but there are no "
            "identifiers (bug).");

        for (const rct::key &identifier : identifiers_of_known_enotes)
        {
            // key image is known if there is a full record associated with this intermediate record's onetime address
            if (m_legacy_contextual_enote_records.find(identifier) == m_legacy_contextual_enote_records.end())
                continue;

            CHECK_AND_ASSERT_THROW_MES(identifier == *(identifiers_of_known_enotes.begin()),
                "add intermediate record (mock enote store): key image is known but there are intermediate "
                "records with this onetime address (a given onetime address should have only intermediate or only "
                "full legacy records).");

            LegacyContextualEnoteRecordV1 temp_full_record{};

            get_legacy_enote_record(new_record.m_record,
                m_legacy_contextual_enote_records.at(identifier).m_record.m_key_image,
                temp_full_record.m_record);
            temp_full_record.m_origin_context = new_record.m_origin_context;

            this->add_record(temp_full_record, changes_inout);
            return;
        }
    }

    // 2. else add the intermediate record or update an existing record's origin context
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_record.m_record.m_enote),
        new_record.m_record.m_amount,
        new_record_identifier);

    if (m_legacy_intermediate_contextual_enote_records.find(new_record_identifier) ==
        m_legacy_intermediate_contextual_enote_records.end())
    {
        // add new intermediate record
        m_legacy_intermediate_contextual_enote_records[new_record_identifier] = new_record;
        changes_inout.emplace_back(NewLegacyIntermediateRecord{new_record_identifier});
    }
    else
    {
        // update intermediate record's origin context
        if (try_update_enote_origin_context_v1(new_record.m_origin_context,
                m_legacy_intermediate_contextual_enote_records[new_record_identifier].m_origin_context))
            changes_inout.emplace_back(UpdatedLegacyIntermediateOriginContext{new_record_identifier});
    }

    // 3. save to the legacy duplicate tracker
    m_tracked_legacy_onetime_address_duplicates[onetime_address_ref(new_record.m_record.m_enote)]
        .insert(new_record_identifier);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::add_record(const LegacyContextualEnoteRecordV1 &new_record,
    std::list<EnoteStoreChange> &changes_inout)
{
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_record.m_record.m_enote),
        new_record.m_record.m_amount,
        new_record_identifier);

    // 1. add the record or update an existing record's contexts
    if (m_legacy_contextual_enote_records.find(new_record_identifier) == m_legacy_contextual_enote_records.end())
    {
        m_legacy_contextual_enote_records[new_record_identifier] = new_record;
        changes_inout.emplace_back(NewLegacyRecord{new_record_identifier});
    }
    else
    {
        update_contextual_enote_record_contexts_v1(new_record.m_origin_context,
                new_record.m_spent_context,
                m_legacy_contextual_enote_records[new_record_identifier].m_origin_context,
                m_legacy_contextual_enote_records[new_record_identifier].m_spent_context
            );
        changes_inout.emplace_back(UpdatedLegacySpentContext{new_record_identifier});
        changes_inout.emplace_back(UpdatedLegacyOriginContext{new_record_identifier});
    }

    // 2. if this enote is located in the legacy key image tracker for seraphis txs, update with the tracker's spent
    //    context
    if (m_legacy_key_images_in_sp_selfsends.find(new_record.m_record.m_key_image) !=
        m_legacy_key_images_in_sp_selfsends.end())
    {
        // update the record's spent context
        try_update_enote_spent_context_v1(m_legacy_key_images_in_sp_selfsends.at(new_record.m_record.m_key_image),
            m_legacy_contextual_enote_records[new_record_identifier].m_spent_context);
        //don't add change record: assume it would be redundant

        // note: do not reset the tracker's spent context here, the tracker is a helper cache for the scanning process
        //       and should only be mutated by that code
    }

    // 3. if this enote is located in the intermediate enote record map, update the full record with the intermediate
    //    record's origin context
    if (m_legacy_intermediate_contextual_enote_records.find(new_record_identifier) !=
        m_legacy_intermediate_contextual_enote_records.end())
    {
        // update the record's origin context
        try_update_enote_origin_context_v1(
                m_legacy_intermediate_contextual_enote_records.at(new_record_identifier).m_origin_context,
                m_legacy_contextual_enote_records[new_record_identifier].m_origin_context
            );
        //don't add change record: assume it would be redundant
    }

    // 4. there may be other full legacy enote records with this record's key image, use them to update the spent context
    for (const rct::key &legacy_enote_identifier :
            m_tracked_legacy_onetime_address_duplicates[onetime_address_ref(new_record.m_record.m_enote)])
    {
        // a. skip identifiers not in the full legacy records map
        if (m_legacy_contextual_enote_records.find(legacy_enote_identifier) == m_legacy_contextual_enote_records.end())
            continue;

        // b. update the spent context
        try_update_enote_spent_context_v1(
            m_legacy_contextual_enote_records.at(legacy_enote_identifier).m_spent_context,
            m_legacy_contextual_enote_records[new_record_identifier].m_spent_context);
        //don't add change record: assume it would be redundant
    }

    // 5. remove the intermediate record with this identifier (must do this before importing the key image, since
    //    the key image importer assumes the intermediate and full legacy maps don't have any overlap)
    if (m_legacy_intermediate_contextual_enote_records.erase(new_record_identifier) > 0)
        changes_inout.emplace_back(RemovedLegacyIntermediateRecord{new_record_identifier});

    // 6. save to the legacy duplicate tracker
    m_tracked_legacy_onetime_address_duplicates[onetime_address_ref(new_record.m_record.m_enote)]
        .insert(new_record_identifier);

    // 7. save to the legacy key image set
    m_legacy_key_images[new_record.m_record.m_key_image] = onetime_address_ref(new_record.m_record.m_enote);

    // 8. import this key image to force-promote all intermediate records with different identifiers to full records
    this->try_import_legacy_key_image(new_record.m_record.m_key_image,
        onetime_address_ref(new_record.m_record.m_enote),
        changes_inout);
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::add_record(const SpContextualEnoteRecordV1 &new_record,
    std::list<EnoteStoreChange> &changes_inout)
{
    const crypto::key_image &record_key_image{key_image_ref(new_record)};

    // add the record or update an existing record's contexts
    if (m_sp_contextual_enote_records.find(record_key_image) == m_sp_contextual_enote_records.end())
    {
        m_sp_contextual_enote_records[record_key_image] = new_record;
        changes_inout.emplace_back(NewSpRecord{record_key_image});
    }
    else
    {
        update_contextual_enote_record_contexts_v1(new_record, m_sp_contextual_enote_records[record_key_image]);
        changes_inout.emplace_back(UpdatedSpSpentContext{record_key_image});
        changes_inout.emplace_back(UpdatedSpOriginContext{record_key_image});
    }
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_legacy_with_fresh_found_spent_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        // a. ignore key images with unknown legacy enotes
        if (m_legacy_key_images.find(found_spent_key_image.first) == m_legacy_key_images.end())
            continue;

        // b. check that legacy key image map and tracked onetime address maps are consistent
        CHECK_AND_ASSERT_THROW_MES(m_tracked_legacy_onetime_address_duplicates.find(
                    m_legacy_key_images.at(found_spent_key_image.first)) !=
                m_tracked_legacy_onetime_address_duplicates.end(),
            "enote store update with legacy enote records (mock): duplicate tracker is missing a onetime address "
            "(bug).");

        // c. update spent contexts of any enotes associated with this key image
        const auto &identifiers_of_enotes_to_update =
            m_tracked_legacy_onetime_address_duplicates.at(m_legacy_key_images.at(found_spent_key_image.first));

        for (const rct::key &identifier_of_enote_to_update : identifiers_of_enotes_to_update)
        {
            CHECK_AND_ASSERT_THROW_MES(m_legacy_contextual_enote_records.find(identifier_of_enote_to_update) !=
                    m_legacy_contextual_enote_records.end(),
                "enote store update with legacy enote records (mock): full record map is missing identifier (bug).");
            CHECK_AND_ASSERT_THROW_MES(
                    m_legacy_contextual_enote_records[identifier_of_enote_to_update].m_record.m_key_image ==
                    found_spent_key_image.first,
                "enote store update with legacy enote records (mock): full record map is inconsistent (bug).");

            update_contextual_enote_record_contexts_v1(
                m_legacy_contextual_enote_records[identifier_of_enote_to_update].m_origin_context,
                found_spent_key_image.second,
                m_legacy_contextual_enote_records[identifier_of_enote_to_update].m_origin_context,
                m_legacy_contextual_enote_records[identifier_of_enote_to_update].m_spent_context);
            changes_inout.emplace_back(UpdatedLegacySpentContext{identifier_of_enote_to_update});
            changes_inout.emplace_back(UpdatedLegacyOriginContext{identifier_of_enote_to_update});
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::update_sp_with_fresh_found_spent_key_images(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
    std::list<EnoteStoreChange> &changes_inout)
{
    for (const auto &found_spent_key_image : found_spent_key_images)
    {
        // a. ignore enotes with unknown key images
        if (m_sp_contextual_enote_records.find(found_spent_key_image.first) == m_sp_contextual_enote_records.end())
            continue;

        // b. update this enote's spent context
        update_contextual_enote_record_contexts_v1(
            m_sp_contextual_enote_records[found_spent_key_image.first].m_origin_context,
            found_spent_key_image.second,
            m_sp_contextual_enote_records[found_spent_key_image.first].m_origin_context,
            m_sp_contextual_enote_records[found_spent_key_image.first].m_spent_context);
        changes_inout.emplace_back(UpdatedSpSpentContext{found_spent_key_image.first});
        changes_inout.emplace_back(UpdatedSpOriginContext{found_spent_key_image.first});
    }
}
//-------------------------------------------------------------------------------------------------------------------
// MOCK ENOTE STORE INTERNAL
//-------------------------------------------------------------------------------------------------------------------
void SpEnoteStoreMockV1::handle_legacy_key_images_from_sp_selfsends(
    const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
    std::list<EnoteStoreChange> &changes_inout)
{
    // handle each key image
    for (const auto &legacy_key_image_with_spent_context : legacy_key_images_in_sp_selfsends)
    {
        // 1. try to update the spent contexts of legacy enotes that have this key image
        for (auto &mapped_contextual_enote_record : m_legacy_contextual_enote_records)
        {
            // a. skip legacy enotes with different key images
            if (mapped_contextual_enote_record.second.m_record.m_key_image != legacy_key_image_with_spent_context.first)
                continue;

            // b. update the spent context of this legacy enote
            if (try_update_enote_spent_context_v1(legacy_key_image_with_spent_context.second,
                    mapped_contextual_enote_record.second.m_spent_context))
                changes_inout.emplace_back(UpdatedLegacySpentContext{mapped_contextual_enote_record.first});
        }

        // 2. save the key image's spent context in the tracker (or update an existing context)
        // note: these are always saved to help with reorg handling
        try_update_enote_spent_context_v1(legacy_key_image_with_spent_context.second,
            m_legacy_key_images_in_sp_selfsends[legacy_key_image_with_spent_context.first]);
        //don't add change record: the m_legacy_key_images_in_sp_selfsends is an internal cache
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp