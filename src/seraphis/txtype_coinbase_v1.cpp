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
#include "txtype_coinbase_v1.h"

//local headers
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_core_enote_utils.h"
#include "sp_core_types.h"
#include "tx_builder_types.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_validation_context.h"
#include "tx_validators.h"

//third party headers

//standard headers
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void SpTxCoinbaseV1::get_id(rct::key &tx_id_out) const
{
    static const std::string project_name{CRYPTONOTE_NAME};

    // tx_id = H_32(crypto project name, version string, block height, block reward, output enotes, tx supplement)
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(m_tx_semantic_rules_version, version_string);

    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_TRANSACTION_TYPE_COINBASE_V1,
            project_name.size() +
                version_string.size() +
                16 +
                m_outputs.size()*SpCoinbaseEnoteV1::size_bytes() +
                m_tx_supplement.size_bytes()
        };
    transcript.append("project_name", project_name);
    transcript.append("version_string", version_string);
    transcript.append("block_height", m_block_height);
    transcript.append("block_reward", m_block_reward);
    transcript.append("output_enotes", m_outputs);
    transcript.append("tx_supplement", m_tx_supplement);

    sp_hash_to_32(transcript, tx_id_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxCoinbaseV1::size_bytes(const std::size_t num_outputs, const TxExtra &tx_extra)
{
    // size of the transaction as represented in C++
    std::size_t size{0};

    // coinbase input (block height and block reward)
    size += 8 + 8;

    // outputs
    size += num_outputs * SpCoinbaseEnoteV1::size_bytes();

    // extra data in tx
    size += SpTxSupplementV1::size_bytes(num_outputs, tx_extra, false);  //without shared ephemeral pubkey assumption

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxCoinbaseV1::size_bytes() const
{
    return SpTxCoinbaseV1::size_bytes(m_outputs.size(), m_tx_supplement.m_tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxCoinbaseV1::weight(const std::size_t num_outputs, const TxExtra &tx_extra)
{
    return SpTxCoinbaseV1::size_bytes(num_outputs, tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxCoinbaseV1::weight() const
{
    return SpTxCoinbaseV1::weight(m_outputs.size(), m_tx_supplement.m_tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_coinbase_v1(const SpTxCoinbaseV1::SemanticRulesVersion semantic_rules_version,
    const std::uint64_t block_height,
    const rct::xmr_amount block_reward,
    std::vector<SpCoinbaseEnoteV1> outputs,
    SpTxSupplementV1 tx_supplement,
    SpTxCoinbaseV1 &tx_out)
{
    tx_out.m_tx_semantic_rules_version = semantic_rules_version;
    tx_out.m_block_height = block_height;
    tx_out.m_block_reward = block_reward;
    tx_out.m_outputs = std::move(outputs);
    tx_out.m_tx_supplement = std::move(tx_supplement);

    CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(tx_out), "Failed to assemble an SpTxCoinbaseV1.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_coinbase_v1(const SpTxCoinbaseV1::SemanticRulesVersion semantic_rules_version,
    const SpCoinbaseTxProposalV1 &tx_proposal,
    SpTxCoinbaseV1 &tx_out)
{
    // 1. check tx proposal semantics
    check_v1_coinbase_tx_proposal_semantics_v1(tx_proposal);

    // 2. extract outputs from the tx proposal
    std::vector<SpCoinbaseOutputProposalV1> output_proposals;
    tx_proposal.get_coinbase_output_proposals_v1(output_proposals);

    // 3. extract info from output proposals
    std::vector<SpCoinbaseEnoteV1> output_enotes;
    SpTxSupplementV1 tx_supplement;
    make_v1_coinbase_outputs_v1(output_proposals, output_enotes, tx_supplement.m_output_enote_ephemeral_pubkeys);

    // 4. collect full memo
    finalize_tx_extra_v1(tx_proposal.m_partial_memo, output_proposals, tx_supplement.m_tx_extra);

    // 5. finish tx
    make_seraphis_tx_coinbase_v1(semantic_rules_version,
        tx_proposal.m_block_height,
        tx_proposal.m_block_reward,
        std::move(output_enotes),
        std::move(tx_supplement),
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_coinbase_v1(const SpTxCoinbaseV1::SemanticRulesVersion semantic_rules_version,
    const std::uint64_t block_height,
    const rct::xmr_amount block_reward,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxCoinbaseV1 &tx_out)
{
    // make a coinbase tx proposal
    SpCoinbaseTxProposalV1 tx_proposal;
    make_v1_coinbase_tx_proposal_v1(block_height,
        block_reward,
        std::move(normal_payment_proposals),
        std::move(additional_memo_elements),
        tx_proposal);

    // finish tx
    make_seraphis_tx_coinbase_v1(semantic_rules_version, tx_proposal, tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigCoinbaseComponentCountsV1 semantic_config_coinbase_component_counts_v1(
    const SpTxCoinbaseV1::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigCoinbaseComponentCountsV1 config{};

    if (tx_semantic_rules_version == SpTxCoinbaseV1::SemanticRulesVersion::MOCK)
    {
        config.m_min_outputs = 0;
        config.m_max_outputs = 100000;
    }
    else if (tx_semantic_rules_version == SpTxCoinbaseV1::SemanticRulesVersion::ONE)
    {
        config.m_min_outputs = 1;
        config.m_max_outputs = config::SP_MAX_COINBASE_OUTPUTS_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for component counts with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_semantics<SpTxCoinbaseV1>(const SpTxCoinbaseV1 &tx)
{
    // validate component counts (num inputs/outputs/etc.)
    if (!validate_sp_semantics_coinbase_component_counts_v1(
            semantic_config_coinbase_component_counts_v1(tx.m_tx_semantic_rules_version),
            tx.m_outputs.size(),
            tx.m_tx_supplement.m_output_enote_ephemeral_pubkeys.size()))
        return false;

    // validate output serialization semantics
    if (!validate_sp_semantics_output_serialization_v1(tx.m_outputs))
        return false;

    // validate layout (sorting, uniqueness) of outputs and tx supplement
    if (!validate_sp_semantics_coinbase_layout_v1(tx.m_outputs,
            tx.m_tx_supplement.m_output_enote_ephemeral_pubkeys,
            tx.m_tx_supplement.m_tx_extra))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_key_images<SpTxCoinbaseV1>(const SpTxCoinbaseV1&, const TxValidationContext&)
{
    // coinbase txs have no key images
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_amount_balance<SpTxCoinbaseV1>(const SpTxCoinbaseV1 &tx)
{
    // balance proof
    if (!validate_sp_coinbase_amount_balance_v1(tx.m_block_reward, tx.m_outputs))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_input_proofs<SpTxCoinbaseV1>(const SpTxCoinbaseV1&, const TxValidationContext&)
{
    // coinbase txs have no input prooofs
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_txs_batchable<SpTxCoinbaseV1>(const std::vector<const SpTxCoinbaseV1*>&, const TxValidationContext&)
{
    // coinbase txs have no batchable proofs to verify
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
