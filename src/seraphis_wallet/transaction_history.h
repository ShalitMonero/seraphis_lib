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

// Supporting types for Jamtis (address index, address tag hint, address tag, etc.).

#pragma once

// local headers
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "ringct/rctTypes.h"

//third party headers
#include "boost/range/iterator_range.hpp"
#include <boost/range.hpp>

//standard headers
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <unordered_map>
#include <tuple>
#include <unordered_set>
#include <vector>

// forward declarations

// Statement of problem:
// - Find fastest way to go from txid to TransactionRecord
// - Find fastest way to go from a range of blocks or time to TransactionRecord 

// Solution:
// - Scanning the enotes and filling the SpTransactionStore may be slow but can be done
// in the background or recovered from the wallet files. Not much room for improvement either.
// - Finding an entry (SpContextualEnoteRecord) is optimized by blockheight and txid (log n).

// Given that the new key_images are available whenever an update on the enote_store occurs 
// Sort SpTxStore by txid and blockheight 

// When a transfer is done:
// - Entry will be created to store outlays/key_images/amount/fee for a certain txid
// - Enote_store will be updated
// - Enote_store will issue a notification returning key_images of updated enotes
// - SpTransactionStore will update confirmed_txids(by blockheight)/unconfirmed_txids/offchain_txids

using namespace sp::jamtis;
using namespace sp;

typedef boost::iterator_range<std::_Rb_tree_iterator<std::pair<const unsigned long, rct::key>>> range_txids_by_block_or_time;

enum class SpTxStatus
{
    CONFIRMED,
    UNCONFIRMED,
    OFFCHAIN
};

struct TxView
{
    std::string block;
    std::string direction;
    std::string unlocked;
    std::string timestamp;
    std::string amount;
    std::string hash;
    std::string fee;
    std::string destinations;
    std::string note;
};

struct TransactionRecordV1
{
    // key images of spent enotes for tracking purposes
    std::vector<crypto::key_image> legacy_spent_enotes;
    std::vector<crypto::key_image> sp_spent_enotes;

    // sent funds
    std::vector<std::pair<JamtisDestinationV1, rct::xmr_amount>> outlays;

    // fees and total sent: 
    // useful to store here also instead of looking directly at the enotes and blockchain
    rct::xmr_amount amount_sent;
    rct::xmr_amount fee_sent;
};

class SpTransactionStoreV1
{
    // quickly find TransactionRecordV1 from txid
    std::unordered_map<rct::key, TransactionRecordV1> m_tx_records;

    // sort by blockheight to find last transactions or txs 
    // in a specific time range
    std::multimap<std::uint64_t,rct::key, std::greater<std::uint64_t>> m_confirmed_txids;

    // sort by timestamp instead of blockheight
    std::multimap<std::uint64_t, rct::key,std::greater<std::uint64_t>> m_unconfirmed_txids;
    std::multimap<std::uint64_t, rct::key,std::greater<std::uint64_t>> m_offchain_txids;

    public:
    // add entry to m_tx_records
    void add_entry_to_tx_records(const rct::key &txid, const TransactionRecordV1 &record);

    // add entry to m_confirmed_txids/m_unconfirmed_txids/m_offchain_txids
    void add_entry_txs(const SpTxStatus tx_status, const uint64_t block_or_timestamp, const rct::key &txid);
    
    // get pointer to m_confirmed_txids/m_unconfirmed_txids/m_offchain_txids
    std::multimap<std::uint64_t, rct::key,std::greater<std::uint64_t>>* get_pointer_to_tx_status(const SpTxStatus tx_status);

//-----------------------------------------------------------------
/// Update
    // - Methods to update tx_statuses
    // - This component could be launched in a separated thread whenever a notification
    // to update is popped. So the confirmed/unconfirmed/offchain txs will always be updated.

//-----------------------------------------------------------------
/// Get range and enotes
    // get last N confirmed/unconfirmed/offchain txs (ordered by blockheight/timestamp)
    const range_txids_by_block_or_time get_last_N_txs(const SpTxStatus tx_status, const uint64_t N);

    // get specific enotes by txid
    bool get_enotes_from_tx(const rct::key &txid,
    const SpEnoteStore &enote_store,
    std::pair<std::vector<LegacyContextualEnoteRecordV1> ,std::vector<SpContextualEnoteRecordV1>> &enotes_out);

    // get an enote with tx_info
    bool get_representing_enote_from_tx(
        const std::pair<std::vector<LegacyContextualEnoteRecordV1> ,std::vector<SpContextualEnoteRecordV1>> &enotes_in_tx,
        ContextualRecordVariant &contextual_enote_out);
    
//-----------------------------------------------------------------
/// Show transfers

    // Exhibit txs chronologically
    bool get_tx_view(const ContextualRecordVariant &contextual_enote, TxView &tx_view_out);
    
    // Print transactions to screen
    void print_tx_view(const TxView tx_view);


//-----------------------------------------------------------------
/// Get Knowledge proofs

    // get tx_funded_proof
    bool get_tx_funded_proof(const rct::key &txid, 
        const SpEnoteStore &enote_store,
        const crypto::secret_key &sp_spend_privkey,
        const crypto::secret_key &k_view_balance);
};