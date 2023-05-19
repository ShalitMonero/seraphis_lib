// Copyright (c) 2023, The Monero Project
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

#pragma once

// paired header
#include "transaction_history.h"

// local headers
#include "common/container_helpers.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "transaction_utils.h"

// third party headers
#include <boost/range.hpp>
#include <boost/range/iterator_range_core.hpp>

#include "boost/range/iterator_range.hpp"
#include "string_tools.h"

// standard headers
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace sp;

void SpTransactionStoreV1::add_entry_to_tx_records(const rct::key &txid, const TransactionRecordV1 &record)
{
    m_tx_records[txid] = record;
}
//-------------------------------------------------------------------------------------------------------------------
std::multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> *SpTransactionStoreV1::get_pointer_to_tx_status(
    const SpTxStatus tx_status)
{
    // get pointer to corresponding multimap
    std::multimap<std::uint64_t, rct::key, std::greater<std::uint64_t>> *ptr = nullptr;
    switch (tx_status)
    {
        case SpTxStatus::CONFIRMED:
        {
            ptr = &m_confirmed_txids;
            break;
        }
        case SpTxStatus::UNCONFIRMED:
        {
            ptr = &m_unconfirmed_txids;
            break;
        }
        case SpTxStatus::OFFCHAIN:
        {
            ptr = &m_offchain_txids;
            break;
        }
        default:
            break;
    }
    return ptr;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionStoreV1::add_entry_txs(const SpTxStatus tx_status, const uint64_t block_or_timestamp,
                                         const rct::key &txid)
{
    // add entry to corresponding variable
    auto ptr_status = get_pointer_to_tx_status(tx_status);
    ptr_status->emplace(block_or_timestamp, txid);
}
//-------------------------------------------------------------------------------------------------------------------
const range_txids_by_block_or_time SpTransactionStoreV1::get_last_N_txs(const SpTxStatus tx_status, const uint64_t N)
{
    // 1. get pointer
    auto ptr_status = get_pointer_to_tx_status(tx_status);

    // 2. set begin and end iterators to beggining of multimap
    std::multimap<unsigned long, rct::key>::iterator it_begin = ptr_status->begin();
    std::multimap<unsigned long, rct::key>::iterator it_end = ptr_status->begin();

    // 3. get size of multimap
    uint64_t counts{ptr_status->size()};

    // 4. advance the end iterator to the end or to the position N
    if (N < counts)
        std::advance(it_end, N);
    else
        std::advance(it_end, counts);

    // 5. return range
    return boost::make_iterator_range(it_begin, it_end);
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionStoreV1::get_enotes_from_tx(
    const rct::key &txid, const SpEnoteStore &enote_store,
    std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> &enotes_out)
{
    // 1. get TransactionRecord if txid exists
    TransactionRecordV1 tx_rec{};
    if (m_tx_records.find(txid) == m_tx_records.end())
    {
        // TODO: which library to use to show wallet msgs?
        // std::cout << txid << " not found" << std::endl;
        return false;
    }
    else
        tx_rec = m_tx_records[txid];

    // 2. get Sp enotes context
    std::vector<SpContextualEnoteRecordV1> sp_spent;
    for (auto sp_ki : tx_rec.sp_spent_enotes)
    {
        enote_store.try_get_sp_enote_record(sp_ki, tools::add_element(sp_spent));
    }

    // 3. get Legacy enotes context
    std::vector<LegacyContextualEnoteRecordV1> legacy_spent;
    for (auto legacy_ki : tx_rec.legacy_spent_enotes)
    {
        enote_store.try_get_legacy_enote_record(legacy_ki, tools::add_element(legacy_spent));
    }

    // 4. return enotes in a pair
    enotes_out = std::make_pair(legacy_spent, sp_spent);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionStoreV1::get_representing_enote_from_tx(
    const std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> &enotes_in_tx,
    ContextualRecordVariant &contextual_enote_out)
{
    // try to get a sp enote representing the tx
    if (!enotes_in_tx.second.empty())
    {
        contextual_enote_out = enotes_in_tx.second[0];
        return true;
    }
    else
    // try to get a legacy enote representing the tx
    {
        if (!enotes_in_tx.first.empty())
        {
            contextual_enote_out = enotes_in_tx.first[0];
            return true;
        }
        return false;
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionStoreV1::get_tx_view(const ContextualRecordVariant &contextual_enote, TxView &tx_view_out)
{
    // Only a draft. Very simple version.

    // 1. get SpEnoteSpentContext and TransactionRecord from contextual_enote
    SpEnoteSpentContextV1 spent_context{spent_context_ref(contextual_enote)};
    rct::key tx_id{spent_context.transaction_id};
    TransactionRecordV1 tx_record{m_tx_records[tx_id]};

    // 2. fill TxView with info available
    tx_view_out.block = spent_context.block_index == static_cast<std::uint64_t>(-1)
                            ? std::string{"<unknown>"}
                            : std::to_string(spent_context.block_index);
    tx_view_out.direction = "out";
    tx_view_out.timestamp = tools::get_human_readable_timestamp(spent_context.block_timestamp);
    tx_view_out.amount = std::to_string(tx_record.amount_sent);
    tx_view_out.hash = epee::string_tools::pod_to_hex(spent_context.transaction_id);
    tx_view_out.fee = std::to_string(tx_record.fee_sent);
    std::string str_dest{};
    for (auto dest : tx_record.outlays)
    {
        get_str_from_destination(dest.first, str_dest);
        tx_view_out.destinations += str_dest + std::string(" , ");
    }
    tx_view_out.destinations.erase(tx_view_out.destinations.size() - 3, 3);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void SpTransactionStoreV1::print_tx_view(const TxView tx_view)
{
    // Only a draft. Very simple version.

    std::cout << tx_view.block << " | "
    << tx_view.direction << " | " 
    << tx_view.timestamp << " | " 
    << tx_view.amount << " | " 
    << tx_view.hash << " | " 
    << tx_view.fee << " | " 
    << tx_view.destinations << std::endl;
}
//-------------------------------------------------------------------------------------------------------------------
bool SpTransactionStoreV1::get_tx_funded_proof(const rct::key &txid, const SpEnoteStore &enote_store,
                                               const crypto::secret_key &sp_spend_privkey,
                                               const crypto::secret_key &k_view_balance)
{
    std::pair<std::vector<LegacyContextualEnoteRecordV1>, std::vector<SpContextualEnoteRecordV1>> enotes_from_tx{};

    // 1. get enotes and check if txid exists in storage
    if (!get_enotes_from_tx(txid, enote_store, enotes_from_tx)) return false;

    // 2. get random message
    const rct::key message{rct::skGen()};

    // 3. initialize proof struct
    sp::knowledge_proofs::TxFundedProofV1 tx_funded_proof{};

    // 4. make proof
    // TODO: verify legacy enotes too and make proof on whatever is available
    make_tx_funded_proof_v1(message, enotes_from_tx.second[0].record, sp_spend_privkey, k_view_balance,
                            tx_funded_proof);

    // 5. serialize struct

    // 6. prepare to save to file by proof name and date
    return true;
}
//-------------------------------------------------------------------------------------------------------------------