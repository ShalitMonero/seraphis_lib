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

// Mock enote store (with full-featured balance recovery and balance queries).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "enote_store_change_types.h"
#include "seraphis_main/contextual_enote_record_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_map>
#include <unordered_set>

//forward declarations


namespace sp
{
namespace mocks
{

enum class EnoteStoreBalanceUpdateExclusions
{
    LEGACY_FULL,
    LEGACY_INTERMEDIATE,
    SERAPHIS,
    ORIGIN_LEDGER_LOCKED
};

////
// SpEnoteStoreMockV1
// - tracks legacy and seraphis enotes
///
class SpEnoteStoreMockV1 final
{
    // note: in practice it may be better to embed the main input selection logic within the enote store to avoid the
    //       messiness of a friend class; alternatively, just implement enote store endpoints that are useful for input
    //       selection
    friend class InputSelectorMockV1;

public:
//constructors
    /// normal constructor
    SpEnoteStoreMockV1(const std::uint64_t refresh_index,
        const std::uint64_t first_sp_enabled_block_in_chain,
        const std::uint64_t default_spendable_age);

//member functions
    /// get current balance using specified origin/spent statuses and exclusions
    boost::multiprecision::uint128_t get_balance(
        const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
        const std::unordered_set<SpEnoteSpentStatus> &spent_statuses = {},
        const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions = {}) const;
    /// get index of first block the enote store cares about
    std::uint64_t legacy_refresh_index() const { return m_refresh_index;                                              }
    std::uint64_t sp_refresh_index()     const { return std::max(m_refresh_index, m_first_sp_enabled_block_in_chain); }
    /// get index of heighest recorded block (refresh index - 1 if no recorded blocks)
    std::uint64_t top_block_index() const;
    /// get index of heighest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    std::uint64_t top_legacy_fullscanned_block_index()    const { return m_legacy_fullscan_index;    }
    /// get index of heighest block that was legacy partialscanned (view-scan only)
    std::uint64_t top_legacy_partialscanned_block_index() const { return m_legacy_partialscan_index; }
    /// get index of heighest block that was seraphis view-balance scanned
    std::uint64_t top_sp_scanned_block_index()            const { return m_sp_scanned_index;         }

    /// try to get the recorded block id for a given index and specified scan mode
    /// note: during scanning, different scan modes are assumed to 'not see' block ids obtained by a different scan mode;
    ///       this is necessary to reliably recover from reorgs involving multiple scan modes
    bool try_get_block_id_for_legacy_partialscan(const std::uint64_t block_index, rct::key &block_id_out) const;
    bool try_get_block_id_for_legacy_fullscan   (const std::uint64_t block_index, rct::key &block_id_out) const;
    bool try_get_block_id_for_sp                (const std::uint64_t block_index, rct::key &block_id_out) const;
    /// try to get the recorded block id for a given index (checks legacy block ids then seraphis block ids)
    bool try_get_block_id(const std::uint64_t block_index, rct::key &block_id_out) const;
    /// check if any stored enote has a given key image
    bool has_enote_with_key_image(const crypto::key_image &key_image) const;
    /// get the legacy intermediate records
    /// - useful for collecting their onetime addresses and viewkey extensions for key image recovery
    const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1>& legacy_intermediate_records() const
    { return m_legacy_intermediate_contextual_enote_records; }
    /// try to get a legacy enote with a specified key image
    /// - will only return the highest-amount legacy enote among duplicates, and will return false if the
    ///   highest-amount legacy enote is currently in the intermediate records map
    bool try_get_legacy_enote_record(const crypto::key_image &key_image,
        LegacyContextualEnoteRecordV1 &contextual_record_out) const;
    /// try to get a seraphis enote with a specified key image
    bool try_get_sp_enote_record(const crypto::key_image &key_image,
        SpContextualEnoteRecordV1 &contextual_record_out) const;

    /// try to import a legacy key image
    /// PRECONDITION1: the legacy key image was computed from/for the input onetime address
    /// returns false if the onetime address is unknown (e.g. due to a reorg)
    bool try_import_legacy_key_image(const crypto::key_image &legacy_key_image,
        const rct::key &onetime_address,
        std::list<EnoteStoreChange> &changes_inout);
    /// update the legacy fullscan index as part of a legacy key image import cycle
    void update_legacy_fullscan_index_for_import_cycle(const std::uint64_t saved_index);

    /// setters for scan indices
    /// WARNING: misuse of these will mess up the enote store's state (to recover: set index(s) below problem then
    //           rescan)
    /// note: to repair the enote store in case of an exception or other error during an update, save all of the last
    ///       scanned indices from before the update, reset the enote store with them (after the failure), and then re-scan
    ///       to repair
    void set_last_legacy_fullscan_index   (const std::uint64_t new_index);
    void set_last_legacy_partialscan_index(const std::uint64_t new_index);
    void set_last_sp_scanned_index        (const std::uint64_t new_index);

    /// update the store with legacy enote records and associated context
    void update_with_intermediate_legacy_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);
    void update_with_intermediate_legacy_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);
    void update_with_intermediate_legacy_found_spent_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);
    void update_with_legacy_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);
    void update_with_legacy_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);

    /// update the store with seraphis enote records and associated context
    void update_with_sp_records_from_nonledger(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
        std::list<EnoteStoreChange> &changes_inout);
    void update_with_sp_records_from_ledger(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids,
        const std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
        std::list<EnoteStoreChange> &changes_inout);

private:
    /// balance helpers
    boost::multiprecision::uint128_t get_balance_intermediate_legacy(
        const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
        const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
        const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const;
    boost::multiprecision::uint128_t get_balance_full_legacy(
        const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
        const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
        const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const;
    boost::multiprecision::uint128_t get_balance_seraphis(
        const std::unordered_set<SpEnoteOriginStatus> &origin_statuses,
        const std::unordered_set<SpEnoteSpentStatus> &spent_statuses,
        const std::unordered_set<EnoteStoreBalanceUpdateExclusions> &exclusions) const;

    /// update the store with a set of new block ids from the ledger
    void update_with_new_blocks_from_ledger_legacy_intermediate(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids,
        std::list<EnoteStoreChange> &changes_inout);
    void update_with_new_blocks_from_ledger_legacy_full(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids,
        std::list<EnoteStoreChange> &changes_inout);
    void update_with_new_blocks_from_ledger_sp(const std::uint64_t first_new_block,
        const rct::key &alignment_block_id,
        const std::vector<rct::key> &new_block_ids,
        std::list<EnoteStoreChange> &changes_inout);

    /// clean maps based on new legacy found spent key images
    void clean_maps_for_found_spent_legacy_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);
    /// clean maps based on details of removed legacy enotes
    void clean_maps_for_removed_legacy_enotes(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        const std::unordered_map<rct::key, std::unordered_set<rct::key>> &mapped_identifiers_of_removed_enotes,
        const std::unordered_map<rct::key, crypto::key_image> &mapped_key_images_of_removed_enotes,
        const std::function<bool(const SpEnoteSpentContextV1&)> &spent_context_clearable_func,
        std::list<EnoteStoreChange> &changes_inout);
    /// clean up legacy state to prepare for adding fresh legacy enotes and key images
    void clean_maps_for_legacy_nonledger_update(const SpEnoteOriginStatus nonledger_origin_status,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);
    /// clean up legacy state to prepare for adding fresh legacy enotes and key images
    void clean_maps_for_legacy_ledger_update(const std::uint64_t first_new_block,
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);

    /// clean maps based on tx ids of removed seraphis enotes
    void clean_maps_for_removed_sp_enotes(const std::unordered_set<rct::key> &tx_ids_of_removed_enotes,
        std::list<EnoteStoreChange> &changes_inout);
    /// clean up seraphis state to prepare for adding fresh non-ledger seraphis enotes and key images and legacy key images
    void clean_maps_for_sp_nonledger_update(const SpEnoteOriginStatus nonledger_origin_status,
        std::list<EnoteStoreChange> &changes_inout);
    /// clean up seraphis state to prepare for adding fresh seraphis enotes and key images and legacy key images
    void clean_maps_for_sp_ledger_update(const std::uint64_t first_new_block,
        std::list<EnoteStoreChange> &changes_inout);

    /// add a record
    void add_record(const LegacyContextualIntermediateEnoteRecordV1 &new_record,
        std::list<EnoteStoreChange> &changes_inout);
    void add_record(const LegacyContextualEnoteRecordV1 &new_record,
        std::list<EnoteStoreChange> &changes_inout);
    void add_record(const SpContextualEnoteRecordV1 &new_record,
        std::list<EnoteStoreChange> &changes_inout);

    /// update legacy state with fresh legacy key images that were found to be spent
    void update_legacy_with_fresh_found_spent_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);
    /// update seraphis state with fresh seraphis key images that were found to be spent
    void update_sp_with_fresh_found_spent_key_images(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images,
        std::list<EnoteStoreChange> &changes_inout);

    /// cache legacy key images obtained from seraphis selfsends (i.e. ALL legacy key images spent by user in seraphis txs)
    void handle_legacy_key_images_from_sp_selfsends(
        const std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfsends,
        std::list<EnoteStoreChange> &changes_inout);

//member variables
protected:
    /// intermediate legacy enotes (unknown key images): mapped to H32(Ko, a)
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1>
        m_legacy_intermediate_contextual_enote_records;
    /// legacy enotes: mapped to H32(Ko, a)
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> m_legacy_contextual_enote_records;
    /// seraphis enotes
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> m_sp_contextual_enote_records;

    /// saved legacy key images from txs with seraphis selfsends (i.e. txs we created)
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> m_legacy_key_images_in_sp_selfsends;
    /// legacy H32(Ko, a) identifiers mapped to onetime addresses, for dealing with enotes that have duplicated key images
    /// note: the user can receive multiple legacy enotes with the same identifier, but those are treated as equivalent,
    ///       which should only cause problems for users if the associated tx memos are different (very unlikely scenario)
    std::unordered_map<rct::key, std::unordered_set<rct::key>> m_tracked_legacy_onetime_address_duplicates;
    /// all legacy onetime addresses attached to known legacy enotes, mapped to key images
    /// note: might not include all entries in 'm_legacy_key_images_in_sp_selfsends' if some corresponding enotes are
    //        unknown
    std::unordered_map<crypto::key_image, rct::key> m_legacy_key_images;

    /// refresh index
    std::uint64_t m_refresh_index{0};
    /// stored block ids in range: [refresh index, end of known legacy-supporting chain]
    std::vector<rct::key> m_legacy_block_ids;
    /// stored block ids in range:
    ///   [max(refresh index, first seraphis-enabled block), end of known seraphis-supporting chain]
    std::vector<rct::key> m_sp_block_ids;

    /// heighest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    std::uint64_t m_legacy_fullscan_index{static_cast<std::uint64_t>(-1)};
    /// heighest block that was legacy partialscanned (view-scan only)
    std::uint64_t m_legacy_partialscan_index{static_cast<std::uint64_t>(-1)};
    /// heighest block that was seraphis view-balance scanned
    std::uint64_t m_sp_scanned_index{static_cast<std::uint64_t>(-1)};

    /// configuration value: the first ledger block that can contain seraphis txs
    std::uint64_t m_first_sp_enabled_block_in_chain{static_cast<std::uint64_t>(-1)};
    /// configuration value: default spendable age; an enote is considered 'spendable' in the next block if it's
    //      on-chain and the hext index is >= 'origin index + max(1, default_spendable_age)'; legacy enotes also have
    //      an unlock_time attribute on top of the default spendable age
    std::uint64_t m_default_spendable_age{0};
};

} //namespace mocks
} //namespace sp