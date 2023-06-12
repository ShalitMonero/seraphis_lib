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

// local headers
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "seraphis_main/sp_knowledge_proof_types.h"
#include "ringct/rctTypes.h"
#include "seraphis_impl/serialization_demo_types.h"

//third party headers
#include "boost/range/iterator_range.hpp"
#include "seraphis_wallet/transaction_history.h"
#include "serialization/containers.h"
#include "serialization/serialization.h"
#include <boost/range.hpp>
#include "serialization/binary_archive.h"

//standard headers
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <unordered_map>
#include <tuple>
#include <unordered_set>
#include <vector>


struct ser_EnoteStoreV1
{
        /// legacy intermediate enotes: [ legacy identifier : legacy intermediate record ]
    serializable_unordered_map<rct::key, ser_LegacyContextualIntermediateEnoteRecordV1>
        m_legacy_intermediate_contextual_enote_records;
    /// legacy enotes: [ legacy identifier : legacy record ]
    serializable_unordered_map<rct::key, ser_LegacyContextualEnoteRecordV1> m_legacy_contextual_enote_records;
    /// seraphis enotes: [ seraphis KI : seraphis record ]
    serializable_unordered_map<crypto::key_image, ser_SpContextualEnoteRecordV1> m_sp_contextual_enote_records;

    /// saved legacy key images from txs with seraphis selfsends (i.e. from txs we created)
    /// [ legacy KI : spent context ]
    serializable_unordered_map<crypto::key_image, ser_SpEnoteSpentContextV1> m_legacy_key_images_in_sp_selfsends;
    /// legacy duplicate tracker for dealing with enotes that have duplicated key images
    /// note: the user can receive multiple legacy enotes with the same identifier, but those are treated as equivalent,
    ///       which should only cause problems for users if the associated tx memos are different (very unlikely scenario)
    /// [ Ko : [ legacy identifier ] ]
    serializable_unordered_map<rct::key, std::unordered_set<rct::key>> m_tracked_legacy_onetime_address_duplicates;
    /// legacy onetime addresses attached to known legacy enotes
    /// note: might not include all entries in 'm_legacy_key_images_in_sp_selfsends' if some corresponding enotes are
    //        unknown
    /// [ legacy KI : legacy Ko ]
    std::unordered_map<crypto::key_image, rct::key> m_legacy_key_images;

    BEGIN_SERIALIZE_OBJECT()
        FIELD(m_legacy_intermediate_contextual_enote_records)
        FIELD(m_legacy_contextual_enote_records)
        FIELD(m_sp_contextual_enote_records)
        FIELD(m_legacy_key_images_in_sp_selfsends)
        FIELD(m_tracked_legacy_onetime_address_duplicates)
        FIELD(m_legacy_key_images)
    END_SERIALIZE()
};

struct ser_TransactionRecordV1
{
    // key images of spent enotes for tracking purposes
    std::vector<crypto::key_image> legacy_spent_enotes;
    std::vector<crypto::key_image> sp_spent_enotes;

    // sent funds
    std::vector<std::pair<sp::serialization::ser_JamtisDestinationV1, rct::xmr_amount>> outlays;

    // fees and total sent: 
    // useful to store here also instead of looking directly at the enotes and blockchain
    rct::xmr_amount amount_sent;
    rct::xmr_amount fee_sent;

    BEGIN_SERIALIZE_OBJECT()
        FIELD(legacy_spent_enotes)
        FIELD(sp_spent_enotes)
        FIELD(outlays)
        FIELD(amount_sent)
        FIELD(fee_sent)
    END_SERIALIZE()
};

struct ser_SpTransactionStoreV1
{
    // quickly find TransactionRecordV1 from txid
    serializable_unordered_map<rct::key, ser_TransactionRecordV1> tx_records;
    // std::unordered_map<rct::key, TransactionRecordV1> tx_records;

    // sort by blockheight to find last transactions or txs 
    // in a specific time range
    // std::multimap<std::uint64_t,rct::key, std::greater<std::uint64_t>> confirmed_txids;
    serializable_multimap<std::uint64_t,rct::key, std::greater<std::uint64_t>> confirmed_txids;

    // sort by timestamp instead of blockheight
    // std::multimap<std::uint64_t, rct::key,std::greater<std::uint64_t>> unconfirmed_txids;
    // std::multimap<std::uint64_t, rct::key,std::greater<std::uint64_t>> offchain_txids;

    serializable_multimap<std::uint64_t, rct::key,std::greater<std::uint64_t>> unconfirmed_txids;
    serializable_multimap<std::uint64_t, rct::key,std::greater<std::uint64_t>> offchain_txids;

    BEGIN_SERIALIZE_OBJECT()
        FIELD(tx_records)
        FIELD(confirmed_txids)
        FIELD(unconfirmed_txids)
        FIELD(offchain_txids)
    END_SERIALIZE()

};


void make_serializable_transaction_record_v1(const TransactionRecordV1 &tx_rec, ser_TransactionRecordV1 &ser_tx_rec);
void make_serializable_sp_transaction_store_v1(const SpTransactionStoreV1 &tx_store, ser_SpTransactionStoreV1 &ser_tx_store);

void recover_transaction_record_v1(const ser_TransactionRecordV1 &ser_tx_rec,TransactionRecordV1 &tx_rec);
void recover_sp_transaction_store_v1(const ser_SpTransactionStoreV1 &ser_tx_store,SpTransactionStoreV1 &tx_store);

void make_serializable_enote_store(const SpEnoteStore* enote, const ser_EnoteStoreV1* ser_enote);
void recover_serializable_enote_store(const SpEnoteStore* enote, const ser_EnoteStoreV1* ser_enote);