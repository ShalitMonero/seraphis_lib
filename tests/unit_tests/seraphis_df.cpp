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

#include "crypto/crypto.h"
#include "crypto/x25519.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_address_tag_utils.h"
#include "seraphis/jamtis_address_utils.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_core_types.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_binned_reference_set_utils.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builder_types_legacy.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_legacy_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_component_types_legacy.h"
#include "seraphis/tx_discretized_fee.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_record_utils.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_ref_set_index_mapper_flat.h"
#include "seraphis/txtype_squashed_v1.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_misc_utils.h"
#include "seraphis_mocks/seraphis_mocks.h"

#include "string_tools.h"
// #include "serialization/binary_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"


#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <algorithm>
#include <memory>
#include <vector>

static void make_sp_txtype_squashed_v1(const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    const std::size_t num_random_memo_elements,
    const std::vector<rct::xmr_amount> &in_legacy_amounts,
    const std::vector<rct::xmr_amount> &in_sp_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const sp::DiscretizedFee &discretized_transaction_fee,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    sp::MockLedgerContext &ledger_context_inout,
    sp::SpTxSquashedV1 &tx_out)
{
    /// build a tx from base components
    using namespace sp;

    rct::xmr_amount raw_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_transaction_fee, raw_transaction_fee),
        "SpTxSquashedV1 (unit test): tried to raw make tx with invalid discretized fee.");

    CHECK_AND_ASSERT_THROW_MES(in_legacy_amounts.size() + in_sp_amounts.size() > 0,
        "SpTxSquashedV1 (unit test): tried to raw make tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "SpTxSquashedV1: tried to raw make tx without any outputs.");

    std::vector<rct::xmr_amount> all_in_amounts{in_legacy_amounts};
    all_in_amounts.insert(all_in_amounts.end(), in_sp_amounts.begin(), in_sp_amounts.end());
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(all_in_amounts, out_amounts, raw_transaction_fee),
        "SpTxSquashedV1 (unit test): tried to raw make tx with unbalanced amounts.");

    // make wallet spendbase privkeys (master keys for legacy and seraphis)
    const crypto::secret_key legacy_spend_privkey{rct::rct2sk(rct::skGen())};
    const crypto::secret_key sp_spend_privkey{rct::rct2sk(rct::skGen())};

    // make mock legacy input proposals
    std::vector<LegacyInputProposalV1> legacy_input_proposals{
            gen_mock_legacy_input_proposals_v1(legacy_spend_privkey, in_legacy_amounts)
        };

    // make mock seraphis input proposals
    std::vector<SpInputProposalV1> sp_input_proposals{gen_mock_sp_input_proposals_v1(sp_spend_privkey, in_sp_amounts)};

    // make mock output proposals
    std::vector<SpOutputProposalV1> output_proposals{
            gen_mock_sp_output_proposals_v1(out_amounts, num_random_memo_elements)
        };

    // for 2-out txs, can only have one unique enote ephemeral pubkey
    if (output_proposals.size() == 2)
        output_proposals[1].m_enote_ephemeral_pubkey = output_proposals[0].m_enote_ephemeral_pubkey;

    // pre-sort inputs and outputs (doing this here makes everything else easier)
    std::sort(legacy_input_proposals.begin(), legacy_input_proposals.end());
    std::sort(sp_input_proposals.begin(), sp_input_proposals.end());
    std::sort(output_proposals.begin(), output_proposals.end());

    // make mock memo elements
    std::vector<ExtraFieldElement> additional_memo_elements;
    additional_memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element : additional_memo_elements)
        element.gen();

    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(semantic_rules_version, version_string);

    // tx components
    std::vector<LegacyEnoteImageV2> legacy_input_images;
    std::vector<SpEnoteImageV1> sp_input_images;
    std::vector<SpEnoteV1> outputs;
    SpBalanceProofV1 balance_proof;
    std::vector<LegacyRingSignatureV3> tx_legacy_ring_signatures;
    std::vector<SpImageProofV1> tx_sp_image_proofs;
    std::vector<SpAlignableMembershipProofV1> tx_sp_alignable_membership_proofs;
    std::vector<SpMembershipProofV1> tx_sp_membership_proofs;
    SpTxSupplementV1 tx_supplement;

    // info shuttles for making components
    std::vector<rct::xmr_amount> output_amounts;
    std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
    rct::key tx_proposal_prefix;
    std::vector<rct::xmr_amount> input_legacy_amounts;
    std::vector<rct::xmr_amount> input_sp_amounts;
    std::vector<crypto::secret_key> legacy_input_image_amount_commitment_blinding_factors;
    std::vector<crypto::secret_key> sp_input_image_amount_commitment_blinding_factors;

    legacy_input_images.reserve(legacy_input_proposals.size());
    sp_input_images.reserve(sp_input_proposals.size());

    // make everything
    make_v1_outputs_v1(output_proposals,
        outputs,
        output_amounts,
        output_amount_commitment_blinding_factors,
        tx_supplement.m_output_enote_ephemeral_pubkeys);
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        accumulate_extra_field_elements(output_proposal.m_partial_memo, additional_memo_elements);
    make_tx_extra(std::move(additional_memo_elements), tx_supplement.m_tx_extra);
    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
    {
        legacy_input_images.emplace_back();
        legacy_input_proposal.get_enote_image_v2(legacy_input_images.back());
    }
    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
    {
        sp_input_images.emplace_back();
        sp_input_proposal.get_enote_image_v1(sp_input_images.back());
    }
    make_tx_proposal_prefix_v1(version_string,
        legacy_input_images,
        sp_input_images,
        outputs,
        tx_supplement,
        discretized_transaction_fee,
        tx_proposal_prefix);
    std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps{
            gen_mock_legacy_ring_signature_preps_v1(tx_proposal_prefix,
                legacy_input_proposals,
                legacy_ring_size,
                ledger_context_inout)
        };
    make_v3_legacy_ring_signatures_v1(std::move(legacy_ring_signature_preps),
        legacy_spend_privkey,
        tx_legacy_ring_signatures);
    make_v1_image_proofs_v1(sp_input_proposals,
        tx_proposal_prefix,
        sp_spend_privkey,
        tx_sp_image_proofs);
    prepare_legacy_input_commitment_factors_for_balance_proof_v1(legacy_input_proposals,
        input_legacy_amounts,
        legacy_input_image_amount_commitment_blinding_factors);
    prepare_input_commitment_factors_for_balance_proof_v1(sp_input_proposals,
        input_sp_amounts,
        sp_input_image_amount_commitment_blinding_factors);
    make_v1_balance_proof_v1(input_legacy_amounts,
        input_sp_amounts, //note: must range proof seraphis input image commitments in squashed enote model
        output_amounts,
        raw_transaction_fee,
        legacy_input_image_amount_commitment_blinding_factors,
        sp_input_image_amount_commitment_blinding_factors,
        output_amount_commitment_blinding_factors,
        balance_proof);
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps{
            gen_mock_sp_membership_proof_preps_v1(sp_input_proposals,
                ref_set_decomp_n,
                ref_set_decomp_m,
                bin_config,
                ledger_context_inout)
        };
    make_v1_membership_proofs_v1(std::move(sp_membership_proof_preps),
        tx_sp_alignable_membership_proofs);  //alignable membership proofs could theoretically be user inputs as well
    align_v1_membership_proofs_v1(sp_input_images, std::move(tx_sp_alignable_membership_proofs), tx_sp_membership_proofs);

    make_seraphis_tx_squashed_v1(semantic_rules_version, std::move(legacy_input_images), std::move(sp_input_images),
        std::move(outputs), std::move(balance_proof), std::move(tx_legacy_ring_signatures), std::move(tx_sp_image_proofs),
        std::move(tx_sp_membership_proofs), std::move(tx_supplement), discretized_transaction_fee, tx_out);
}
//-------------------------------------------------------------------------------------------------------------------

//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_df, transfer_test)
{
    //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)
    // using namespace sp;
    // using namespace jamtis;


    // /// make two users

    // // a. user keys
    // jamtis_mock_keys user_keys_A;
    // jamtis_mock_keys user_keys_B;

    // rct::key k_m_A;
    // rct::key k_vb_A;
    // epee::string_tools::hex_to_pod("b24d3b75b10bc4e4e737f72cc0c10f4bef78b3339a0a25c92ea95d18784c2e05", k_m_A);
    // epee::string_tools::hex_to_pod("846f61dcfbcece775a7a883c1766674d5686e2acb7a3d1b3dc7a10ec1b7baa06", k_vb_A);

    // rct::key k_m_B;
    // rct::key k_vb_B;
    // epee::string_tools::hex_to_pod("0edab6edb15e61ab48dfecdc1e7f6472c70e08df939dac3419b6499d8a77500e", k_m_B);
    // epee::string_tools::hex_to_pod("857e2670026920cdcd8c5f282536a6218947c8e0811383c755a42377368a2508", k_vb_B);
    // make_jamtis_keys_defined(k_m_A, k_vb_A, user_keys_A);
    // make_jamtis_keys_defined(k_m_B, k_vb_B, user_keys_B);
    // // make_jamtis_mock_keys(user_keys_B);


    // // c. seraphis user addresses
    // JamtisDestinationV1 destination_A;
    // JamtisDestinationV1 destination_B;
    // // make_random_address_for_user(user_keys_A, destination_A);
    // make_defined_address_for_user(1, user_keys_A, destination_A);
    // make_defined_address_for_user(1, user_keys_B, destination_B);



////////////////////////////////////////////
    // demo making SpTxTypeSquasedV1 with raw tx builder API
    const std::size_t num_txs{1};
    const std::size_t num_ins_outs{1};

    // fake ledger context for this test
    sp::MockLedgerContext ledger_context{0, 10000};

    // prepare input/output amounts
    std::vector<rct::xmr_amount> in_legacy_amounts;
    std::vector<rct::xmr_amount> in_sp_amounts;
    std::vector<rct::xmr_amount> out_amounts;

    for (int i{0}; i < num_ins_outs; ++i)
    {
        in_legacy_amounts.push_back(0);  //initial tx_fee = num_ins_outs
        in_sp_amounts.push_back(4);
        out_amounts.push_back(3);
    }

    // set fee
    const sp::DiscretizedFee discretized_transaction_fee{num_ins_outs};
    rct::xmr_amount real_transaction_fee;
    EXPECT_TRUE(try_get_fee_value(discretized_transaction_fee, real_transaction_fee));

    // add an input to cover any extra fee added during discretization
    const rct::xmr_amount extra_fee_amount{real_transaction_fee - num_ins_outs};

    if (extra_fee_amount > 0)
        in_sp_amounts.push_back(extra_fee_amount);

    // make txs
    std::vector<sp::SpTxSquashedV1> txs;
    std::vector<const sp::SpTxSquashedV1*> tx_ptrs;
    txs.reserve(num_txs);
    tx_ptrs.reserve(num_txs);

    for (std::size_t tx_index{0}; tx_index < num_txs; ++tx_index)
    {
        make_sp_txtype_squashed_v1(16,
            2,
            2,
            sp::SpBinnedReferenceSetConfigV1{
                .m_bin_radius = 1,
                .m_num_bin_members = 2
            },
            3,
            in_legacy_amounts,
            in_sp_amounts,
            out_amounts,
            discretized_transaction_fee,
            sp::SpTxSquashedV1::SemanticRulesVersion::MOCK,
            ledger_context,
            add_element(txs));
        tx_ptrs.push_back(&(txs.back()));
    }

    const sp::TxValidationContextMock tx_validation_context{ledger_context};

    EXPECT_TRUE(sp::validate_txs(tx_ptrs, tx_validation_context));

    // insert key images to ledger
    for (const sp::SpTxSquashedV1 &tx : txs)
        EXPECT_TRUE(sp::try_add_tx_to_ledger(tx, ledger_context));

    // validation should fail due to double-spend
    EXPECT_FALSE(sp::validate_txs(tx_ptrs, tx_validation_context));


//   txs[0].m_sp_membership_proofs[0]
  auto blob = cryptonote::t_serializable_object_to_blob(txs[0].m_sp_membership_proofs[0].m_grootle_proof);



  std::string sig_str = "SpendProofSpV1";


    


}
//-------------------------------------------------------------------------------------------------------------------
