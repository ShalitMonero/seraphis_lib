// Copyright (c) 2021, The Monero Project
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
#include "txtype_squashed_v1.h"

//local headers
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "ledger_context.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_misc_utils.h"
#include "tx_validators.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// semantic validation config: component counts
//-------------------------------------------------------------------------------------------------------------------
static SemanticConfigComponentCountsV1 semantic_config_component_counts_v1(
    const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigComponentCountsV1 config{};

    //TODO: in the squashed model, inputs + outputs must be <= the BP+ pre-generated generator array size
    if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        config.m_min_inputs = 1;
        config.m_max_inputs = 100000;
        config.m_min_outputs = 1;
        config.m_max_outputs = 100000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::ONE)
    {
        config.m_min_inputs = 1;
        config.m_max_inputs = config::SP_MAX_INPUTS_V1;
        config.m_min_outputs = 2;
        config.m_max_outputs = config::SP_MAX_OUTPUTS_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for component counts with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
// semantic validation config: reference set size
//-------------------------------------------------------------------------------------------------------------------
static SemanticConfigRefSetSizeV1 semantic_config_ref_set_size_v1(
    const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigRefSetSizeV1 config{};

    if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        config.m_decom_n_min = 0;
        config.m_decom_n_max = 100000;
        config.m_decom_m_min = 0;
        config.m_decom_m_max = 100000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::ONE)
    {
        config.m_decom_n_min = config::SP_GROOTLE_N_V1;
        config.m_decom_n_max = config::SP_GROOTLE_N_V1;
        config.m_decom_m_min = config::SP_GROOTLE_M_V1;
        config.m_decom_m_max = config::SP_GROOTLE_M_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for ref set sizes with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_size_bytes() const
{
    // doesn't include:
    // - ring member references (e.g. indices or explicit copies)
    // - tx fees
    // - memos
    // - miscellaneous serialization bytes
    std::size_t size{0};

    // input images
    size += m_input_images.size() * SpEnoteImageV1::get_size_bytes();

    // outputs
    size += m_outputs.size() * SpEnoteV1::get_size_bytes();

    // balance proof
    if (m_balance_proof.get() != nullptr)
        size += m_balance_proof->get_size_bytes();

    // membership proofs
    // - assumes all have the same size
    if (m_membership_proofs.size())
        size += m_membership_proofs.size() * m_membership_proofs[0].get_size_bytes();

    // ownership/key-image-legitimacy proof for all inputs
    // - assumes all have the same size
    if (m_image_proofs.size())
        size += m_image_proofs.size() * m_image_proofs[0].get_size_bytes();

    // extra data in tx
    size += m_supplement.get_size_bytes();

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(std::vector<SpEnoteImageV1> input_images,
    std::vector<SpEnoteV1> outputs,
    std::shared_ptr<const SpBalanceProofV1> balance_proof,
    std::vector<SpImageProofV1> image_proofs,
    std::vector<SpMembershipProofV1> membership_proofs,
    SpTxSupplementV1 tx_supplement,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out)
{
    tx_out.m_input_images = std::move(input_images);
    tx_out.m_outputs = std::move(outputs);
    tx_out.m_balance_proof = std::move(balance_proof);
    tx_out.m_image_proofs = std::move(image_proofs);
    tx_out.m_membership_proofs = std::move(membership_proofs);
    tx_out.m_supplement = std::move(tx_supplement);
    tx_out.m_tx_semantic_rules_version = semantic_rules_version;

    CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(tx_out), "Failed to assemble a SpTxSquashedV1.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(SpTxPartialV1 partial_tx,
    std::vector<SpMembershipProofV1> membership_proofs,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out)
{
    // finish tx from pieces
    make_seraphis_tx_squashed_v1(
            std::move(partial_tx.m_input_images),
            std::move(partial_tx.m_outputs),
            std::move(partial_tx.m_balance_proof),
            std::move(partial_tx.m_image_proofs),
            std::move(membership_proofs),
            std::move(partial_tx.m_tx_supplement),
            semantic_rules_version,
            tx_out
        );
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(const std::vector<SpInputProposalV1> &input_proposals,
    std::vector<SpOutputProposalV1> output_proposals,
    const std::vector<SpMembershipReferenceSetV1> &membership_ref_sets,
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpTxSquashedV1 &tx_out)
{
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Tried to make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(output_proposals.size() > 0, "Tried to make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts_sp_v1(input_proposals, output_proposals, 0),
        "Tried to make tx with unbalanced amounts.");  //TODO: include fee in balance check

    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    get_versioning_string(semantic_rules_version, version_string);

    // tx proposal
    SpTxProposalV1 tx_proposal{std::move(output_proposals)};
    rct::key proposal_prefix{tx_proposal.get_proposal_prefix(version_string)};

    // partial inputs
    std::vector<SpTxPartialInputV1> partial_inputs;
    make_v1_tx_partial_inputs_sp_v1(input_proposals, proposal_prefix, partial_inputs);

    // membership proofs (input proposals are assumed to line up with membership ref sets)
    std::vector<SpMembershipProofAlignableV1> tx_membership_proofs_sortable;
    make_v1_tx_membership_proofs_sp_v1(membership_ref_sets, partial_inputs, tx_membership_proofs_sortable);

    // partial tx
    SpTxPartialV1 partial_tx{tx_proposal, std::move(partial_inputs), version_string};

    // line up the the membership proofs with the partial tx's input images (which are sorted)
    std::vector<SpMembershipProofV1> tx_membership_proofs;
    align_v1_tx_membership_proofs_sp_v1(partial_tx.m_input_images,
        std::move(tx_membership_proofs_sortable),
        tx_membership_proofs);

    // finish tx
    make_seraphis_tx_squashed_v1(std::move(partial_tx), std::move(tx_membership_proofs), semantic_rules_version, tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_semantics<SpTxSquashedV1>(const SpTxSquashedV1 &tx)
{
    if (tx.m_balance_proof.get() == nullptr)
        return false;

    // validate component counts (num inputs/outputs/etc.)
    if (!validate_sp_semantics_component_counts_v1(
        semantic_config_component_counts_v1(tx.m_tx_semantic_rules_version),
        tx.m_input_images.size(),
        tx.m_membership_proofs.size(),
        tx.m_image_proofs.size(),
        tx.m_outputs.size(),
        tx.m_supplement.m_output_enote_ephemeral_pubkeys.size(),
        tx.m_balance_proof->m_bpp_proof.V.size()))
    {
        return false;
    }

    // validate input proof reference set sizes
    if (!validate_sp_semantics_ref_set_size_v1(
        semantic_config_ref_set_size_v1(tx.m_tx_semantic_rules_version),
        tx.m_membership_proofs))
    {
        return false;
    }

    // validate linking tag semantics
    if (!validate_sp_semantics_input_images_v1(tx.m_input_images))
    {
        return false;
    }

    // validate input images, membershio proof ref sets, and outputs are sorted
    if (!validate_sp_semantics_sorting_v1(tx.m_membership_proofs, tx.m_input_images, tx.m_outputs))
    {
        return false;
    }

    //TODO: validate memo semantics

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_linking_tags<SpTxSquashedV1>(const SpTxSquashedV1 &tx, const LedgerContext &ledger_context)
{
    // unspentness proof (key images not in ledger)
    if (!validate_sp_linking_tags_v1(tx.m_input_images, ledger_context))
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_amount_balance<SpTxSquashedV1>(const SpTxSquashedV1 &tx, const bool defer_batchable)
{
    // balance proof
    if (!validate_sp_amount_balance_v1(tx.m_input_images, tx.m_outputs, tx.m_balance_proof, defer_batchable))
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_input_proofs<SpTxSquashedV1>(const SpTxSquashedV1 &tx,
    const LedgerContext &ledger_context,
    const bool defer_batchable)
{
    // membership proofs (can be deferred for batching)
    if (!defer_batchable)
    {
        std::vector<const SpMembershipProofV1*> membership_proof_ptrs;
        std::vector<const SpEnoteImage*> input_image_ptrs;
        membership_proof_ptrs.reserve(tx.m_membership_proofs.size());
        input_image_ptrs.reserve(tx.m_input_images.size());

        for (const auto &membership_proof : tx.m_membership_proofs)
            membership_proof_ptrs.push_back(&membership_proof);

        for (const auto &input_image : tx.m_input_images)
            input_image_ptrs.push_back(&(input_image.m_core));

        if (!validate_sp_membership_proofs_v1(membership_proof_ptrs, input_image_ptrs, ledger_context))
        {
            return false;
        }
    }

    // ownership proof (and proof that key images are well-formed)
    std::string version_string;
    version_string.reserve(3);
    get_versioning_string(tx.m_tx_semantic_rules_version, version_string);

    rct::key image_proofs_message{get_tx_image_proof_message_sp_v1(version_string, tx.m_outputs, tx.m_supplement)};

    if (!validate_sp_composition_proofs_v1(tx.m_image_proofs,
        tx.m_input_images,
        image_proofs_message))
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_txs_batchable<SpTxSquashedV1>(const std::vector<const SpTxSquashedV1*> &txs,
    const LedgerContext &ledger_context)
{
    std::vector<const SpMembershipProofV1*> membership_proof_ptrs;
    std::vector<const SpEnoteImage*> input_image_ptrs;
    std::vector<const rct::BulletproofPlus*> range_proof_ptrs;
    membership_proof_ptrs.reserve(txs.size()*20);  //heuristic... (most tx have 1-2 inputs)
    input_image_ptrs.reserve(txs.size()*20);
    range_proof_ptrs.reserve(txs.size());

    // prepare for batch-verification
    for (const SpTxSquashedV1 *tx : txs)
    {
        if (!tx)
            return false;

        // gather membership proof pieces
        for (const auto &membership_proof : tx->m_membership_proofs)
            membership_proof_ptrs.push_back(&membership_proof);

        for (const auto &input_image : tx->m_input_images)
            input_image_ptrs.push_back(&(input_image.m_core));

        // gather range proofs
        const std::shared_ptr<const SpBalanceProofV1> balance_proof{tx->m_balance_proof};

        if (balance_proof.get() == nullptr)
            return false;

        range_proof_ptrs.push_back(&(balance_proof->m_bpp_proof));
    }

    // batch verify membership proofs
    if (!validate_sp_membership_proofs_v1(membership_proof_ptrs, input_image_ptrs, ledger_context))
    {
        return false;
    }

    // batch verify range proofs
    if (!rct::bulletproof_plus_VERIFY(range_proof_ptrs))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
void make_mock_tx<SpTxSquashedV1>(const SpTxParamPack &params,
    const std::vector<rct::xmr_amount> &in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    MockLedgerContext &ledger_context_inout,
    SpTxSquashedV1 &tx_out)
{
    CHECK_AND_ASSERT_THROW_MES(in_amounts.size() > 0, "Tried to make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "Tried to make tx without any outputs.");
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(in_amounts, out_amounts),
        "Tried to make tx with unbalanced amounts.");

    // make mock inputs
    // enote, ks, view key stuff, amount, amount blinding factor
    std::vector<SpInputProposalV1> input_proposals{gen_mock_sp_input_proposals_v1(in_amounts)};

    // make mock outputs
    std::vector<SpOutputProposalV1> output_proposals{gen_mock_sp_output_proposals_v1(out_amounts)};

    // for 2-out tx, the enote ephemeral pubkey is shared by both outputs
    if (output_proposals.size() == 2)
        output_proposals[1].m_enote_ephemeral_pubkey = output_proposals[0].m_enote_ephemeral_pubkey;

    // make mock membership proof ref sets
    std::vector<SpMembershipReferenceSetV1> membership_ref_sets{
            gen_mock_sp_membership_ref_sets_v1(input_proposals,
                params.ref_set_decomp_n,
                params.ref_set_decomp_m,
                ledger_context_inout)
        };

    // make tx
    make_seraphis_tx_squashed_v1(input_proposals, output_proposals, membership_ref_sets,
        SpTxSquashedV1::SemanticRulesVersion::MOCK, tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
