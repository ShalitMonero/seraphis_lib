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
#include "cryptonote_basic/subaddress_index.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/knowledge_proofs.h"
#include "seraphis_core/jamtis_address_tag_utils.h"
#include "seraphis_core/jamtis_address_utils.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_core/sp_core_types.h"
#include "seraphis/tx_base.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_legacy_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/contextual_enote_record_types.h"
#include "seraphis/contextual_enote_record_utils.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis/enote_record_types.h"
#include "seraphis/enote_record_utils.h"
#include "seraphis/enote_scanning.h"
#include "seraphis/enote_scanning_context_simple.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis/tx_fee_calculator_squashed_v1.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selection_output_context_v1.h"
// #include "seraphis/tx_knowledge_proofs.h"
#include "seraphis/txtype_squashed_v1.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_mocks/seraphis_mocks.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <memory>
#include <tuple>
#include <vector>

using namespace sp;
using namespace jamtis;
using namespace sp::mocks;
using namespace jamtis::mocks;


//-------------------------------------------------------------------------------------------------------------------
// TEST(seraphis_audit_proofs, sp_spend_proof_t1)
// {
//     //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)

//     /// config
//     const std::size_t max_inputs{1000};
//     const std::size_t fee_per_tx_weight{1};
//     // const std::size_t legacy_ring_size{2};
//     const std::size_t ref_set_decomp_n{2};
//     const std::size_t ref_set_decomp_m{2};

//     const RefreshLedgerEnoteStoreConfig refresh_config{
//             .m_reorg_avoidance_depth = 1,
//             .m_max_chunk_size = 1,
//             .m_max_partialscan_attempts = 0
//         };

//     const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator for now (fee = fee/weight * 1 weight)

//     const SpBinnedReferenceSetConfigV1 bin_config{
//             .m_bin_radius = 1,
//             .m_num_bin_members = 2
//         };

//     /// mock ledger context for this test
//     MockLedgerContext ledger_context{0, 10000};


//     /// prepare for membership proofs

//     // // a. add enough fake enotes to the ledger so we can reliably make legacy ring signatures
//     // std::vector<rct::xmr_amount> fake_legacy_enote_amounts(static_cast<std::size_t>(legacy_ring_size), 0);
//     // const rct::key fake_legacy_spendkey{rct::pkGen()};
//     // const rct::key fake_legacy_viewkey{rct::pkGen()};

//     // send_legacy_coinbase_amounts_to_user(fake_legacy_enote_amounts,
//     //     fake_legacy_spendkey,
//     //     fake_legacy_viewkey,
//     //     ledger_context);

//     // b. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
//     std::vector<rct::xmr_amount> fake_sp_enote_amounts(
//             static_cast<std::size_t>(compute_bin_width(bin_config.m_bin_radius)),
//             0
//         );
//     JamtisDestinationV1 fake_destination;
//     fake_destination = gen_jamtis_destination_v1();

//     send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);


//     /// make two users

//     // a. user keys
//     legacy_mock_keys legacy_user_keys_A;
//     jamtis_mock_keys user_keys_A;
//     jamtis_mock_keys user_keys_B;
//     make_legacy_mock_keys(legacy_user_keys_A);
//     make_jamtis_mock_keys(user_keys_A);
//     make_jamtis_mock_keys(user_keys_B);

//     // b. legacy user address
//     rct::key legacy_subaddr_spendkey_A;
//     rct::key legacy_subaddr_viewkey_A;
//     cryptonote::subaddress_index legacy_subaddr_index_A;
//     std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map_A;

//     gen_legacy_subaddress(legacy_user_keys_A.Ks,
//         legacy_user_keys_A.k_v,
//         legacy_subaddr_spendkey_A,
//         legacy_subaddr_viewkey_A,
//         legacy_subaddr_index_A);

//     legacy_subaddress_map_A[legacy_subaddr_spendkey_A] = legacy_subaddr_index_A;

//     // c. seraphis user addresses
//     JamtisDestinationV1 destination_A;
//     JamtisDestinationV1 destination_B;
//     make_random_address_for_user(user_keys_A, destination_A);
//     make_random_address_for_user(user_keys_B, destination_B);

//     // d. user enote stores (refresh height = 0; seraphis initial block = 0; default spendable age = 0)
//     SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
//     SpEnoteStoreMockV1 enote_store_B{0, 0, 0};

//     // e. user input selectors
//     const InputSelectorMockV1 input_selector_A{enote_store_A};
//     const InputSelectorMockV1 input_selector_B{enote_store_B};


//     /// initial funding for user A: legacy 4000000 + seraphis 4000000
//     // send_legacy_coinbase_amounts_to_user(
//     //         {1000000, 1000000, 1000000, 1000000},
//     //         legacy_subaddr_spendkey_A,
//     //         legacy_subaddr_viewkey_A,
//     //         ledger_context
//     //     );
//     send_sp_coinbase_amounts_to_user({1000000,1000000,1000000,1000000}, destination_A, ledger_context);


//     /// send funds back and forth between users

//     // A -> B: 6000000
//     refresh_user_enote_store_legacy_full(legacy_user_keys_A.Ks,
//         legacy_subaddress_map_A,
//         legacy_user_keys_A.k_s,
//         legacy_user_keys_A.k_v,
//         refresh_config,
//         ledger_context,
//         enote_store_A);
//     refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
//     ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
//         {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 3000000);
    

//     std::cout << "Balance before tx: "<< enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
//         {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;

//     // make one tx
//     SpTxSquashedV1 single_tx;
//     construct_tx_for_mock_ledger_v1(legacy_mock_keys{},
//         user_keys_A,
//         input_selector_A,
//         fee_calculator,
//         fee_per_tx_weight,
//         max_inputs,
//         {{100000, destination_B, TxExtra{}},{1000000, destination_B, TxExtra{}},{1000000, destination_B, TxExtra{}}},
//         2,
//         ref_set_decomp_n,
//         ref_set_decomp_m,
//         bin_config,
//         ledger_context,
//         single_tx);

//     // validate and submit to the mock ledger
//     const TxValidationContextMock tx_validation_context{ledger_context};

//     CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
//         "transfer funds single mock: validating tx failed.");
//     CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context),
//         "transfer funds single mock: adding tx to mock ledger failed.");

//     refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    
//     std::cout << "Balance after tx: "<< enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
//         {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;

        
//     //Start Spend Proof

//     SpContextualEnoteRecordV1 contextual_record_temp;
//     std::list<SpContextualEnoteRecordV1> contextual_record_list;

//     for (SpEnoteImageV1 key_image : single_tx.m_sp_input_images)
//     {
//         enote_store_A.try_get_sp_enote_record(key_image.m_core.m_key_image, contextual_record_temp);
//         contextual_record_list.emplace_back(contextual_record_temp);
//     }

//     std::vector<SpInputProposalV1> sp_input_proposals;
//     sp_enote_records_to_input_proposals(contextual_record_list,sp_input_proposals);

//     std::vector<SpMembershipProofPrepV1> proofs_preps{gen_mock_sp_membership_proof_preps_v1(
//         sp_input_proposals, single_tx.m_sp_membership_proofs[0].m_ref_set_decomp_n,
//         single_tx.m_sp_membership_proofs[0].m_ref_set_decomp_m, 
//         single_tx.m_sp_membership_proofs[0].m_binned_reference_set.m_bin_config,
//         ledger_context)};
    
//     rct::key tx_id;
//     get_sp_squashed_v1_txid(single_tx, tx_id);

//     SpKnowledgeProofTxSentV1 spend_proof{generate_sp_tx_spend_proof_v1(
//         tx_id, sp_input_proposals, proofs_preps, user_keys_A.k_vb,
//         user_keys_A.k_m)};

//     std::string string_proof{serialize_sp_tx_spend_proof_v1(spend_proof)};

//     SpKnowledgeProofTxSentV1 spend_proof_recovered{deserialize_sp_tx_spend_proof_v1(string_proof,single_tx)};

//     EXPECT_TRUE(verify_sp_tx_spend_proof_v1(spend_proof,single_tx, tx_validation_context));
//     EXPECT_TRUE(verify_sp_tx_spend_proof_v1(spend_proof_recovered,single_tx, tx_validation_context));
// }
// //-------------------------------------------------------------------------------------------------------------------
// //-------------------------------------------------------------------------------------------------------------------
// TEST(seraphis_audit_proofs, sp_out_proof_t1)
// {
//     //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)

//     /// config
//     const std::size_t max_inputs{1000};
//     const std::size_t fee_per_tx_weight{1};
//     // const std::size_t legacy_ring_size{2};
//     const std::size_t ref_set_decomp_n{2};
//     const std::size_t ref_set_decomp_m{2};

//     const RefreshLedgerEnoteStoreConfig refresh_config{
//             .m_reorg_avoidance_depth = 1,
//             .m_max_chunk_size = 1,
//             .m_max_partialscan_attempts = 0
//         };

//     const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator for now (fee = fee/weight * 1 weight)

//     const SpBinnedReferenceSetConfigV1 bin_config{
//             .m_bin_radius = 1,
//             .m_num_bin_members = 2
//         };

//     /// mock ledger context for this test
//     MockLedgerContext ledger_context{0, 10000};


//     /// prepare for membership proofs

//     // // a. add enough fake enotes to the ledger so we can reliably make legacy ring signatures
//     // std::vector<rct::xmr_amount> fake_legacy_enote_amounts(static_cast<std::size_t>(legacy_ring_size), 0);
//     // const rct::key fake_legacy_spendkey{rct::pkGen()};
//     // const rct::key fake_legacy_viewkey{rct::pkGen()};

//     // send_legacy_coinbase_amounts_to_user(fake_legacy_enote_amounts,
//     //     fake_legacy_spendkey,
//     //     fake_legacy_viewkey,
//     //     ledger_context);

//     // b. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
//     std::vector<rct::xmr_amount> fake_sp_enote_amounts(
//             static_cast<std::size_t>(compute_bin_width(bin_config.m_bin_radius)),
//             0
//         );
//     JamtisDestinationV1 fake_destination;
//     fake_destination = gen_jamtis_destination_v1();

//     send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);


//     /// make two users

//     // a. user keys
//     legacy_mock_keys legacy_user_keys_A;
//     jamtis_mock_keys user_keys_A;
//     jamtis_mock_keys user_keys_B;
//     make_legacy_mock_keys(legacy_user_keys_A);
//     make_jamtis_mock_keys(user_keys_A);
//     make_jamtis_mock_keys(user_keys_B);

//     // b. legacy user address
//     rct::key legacy_subaddr_spendkey_A;
//     rct::key legacy_subaddr_viewkey_A;
//     cryptonote::subaddress_index legacy_subaddr_index_A;
//     std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map_A;

//     gen_legacy_subaddress(legacy_user_keys_A.Ks,
//         legacy_user_keys_A.k_v,
//         legacy_subaddr_spendkey_A,
//         legacy_subaddr_viewkey_A,
//         legacy_subaddr_index_A);

//     legacy_subaddress_map_A[legacy_subaddr_spendkey_A] = legacy_subaddr_index_A;

//     // c. seraphis user addresses
//     JamtisDestinationV1 destination_A;
//     JamtisDestinationV1 destination_B;
//     make_random_address_for_user(user_keys_A, destination_A);
//     make_random_address_for_user(user_keys_B, destination_B);

//     // d. user enote stores (refresh height = 0; seraphis initial block = 0; default spendable age = 0)
//     SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
//     SpEnoteStoreMockV1 enote_store_B{0, 0, 0};

//     // e. user input selectors
//     const InputSelectorMockV1 input_selector_A{enote_store_A};
//     const InputSelectorMockV1 input_selector_B{enote_store_B};


//     /// initial funding for user A: legacy 4000000 + seraphis 4000000
//     // send_legacy_coinbase_amounts_to_user(
//     //         {1000000, 1000000, 1000000, 1000000},
//     //         legacy_subaddr_spendkey_A,
//     //         legacy_subaddr_viewkey_A,
//     //         ledger_context
//     //     );
//     send_sp_coinbase_amounts_to_user({1000000,1000000,1000000}, destination_A, ledger_context);


//     /// send funds back and forth between users

//     // A -> B: 6000000
//     refresh_user_enote_store_legacy_full(legacy_user_keys_A.Ks,
//         legacy_subaddress_map_A,
//         legacy_user_keys_A.k_s,
//         legacy_user_keys_A.k_v,
//         refresh_config,
//         ledger_context,
//         enote_store_A);
//     refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
//     ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
//         {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 3000000);
    

//     std::cout << "Balance before tx: "<< enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
//         {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;

//     // make one tx
//     // The wallet should save the successful/sent payment proposals to store the ephemeral_privkeys
//     // Enote record contains the input_context.
//     SpTxSquashedV1 single_tx;
//     std::vector<jamtis::JamtisPaymentProposalV1> normal_payments;
//     rct::key input_context;
//     rct::xmr_amount amount_to_send = 2000000;
//     construct_tx_for_mock_ledger_v1_out_enote_privkey(legacy_mock_keys{},
//         user_keys_A,
//         input_selector_A,
//         fee_calculator,
//         fee_per_tx_weight,
//         max_inputs,
//         {{amount_to_send, destination_B, TxExtra{}}},
//         2,
//         ref_set_decomp_n,
//         ref_set_decomp_m,
//         bin_config,
//         ledger_context,
//         normal_payments,
//         input_context,
//         single_tx);

//     // validate and submit to the mock ledger
//     const TxValidationContextMock tx_validation_context{ledger_context};

//     CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
//         "transfer funds single mock: validating tx failed.");
//     CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context),
//         "transfer funds single mock: adding tx to mock ledger failed.");

//     refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    
//     std::cout << "Balance after tx: "<< enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
//         {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;


//     //Start OutProof

//     //Provide index of jamtis_proposal payment which the proof will be based on
//     size_t i_payment{0};
    
//     SpKnowledgeProofEnoteSentV1 out_proof{generate_sp_enote_send_proof_v1(normal_payments[i_payment].m_enote_ephemeral_privkey, amount_to_send, destination_B, input_context)};
//     std::string out_proof_string{serialize_sp_enote_send_proof_v1(out_proof)};
//     SpKnowledgeProofEnoteSentV1 out_proof_recovered{deserialize_sp_enote_send_proof_v1(out_proof_string)};

//     //One should provide the exact enote that matches the outproof
//     //A simple scanning is done to find if the enote being proved is part of the tx
//     size_t eph_index{0};
//     for (SpEnoteV1 enotes : single_tx.m_outputs)
//     {
//         if (enotes.m_core.m_onetime_address == out_proof.one_time_address)
//         {
//             EXPECT_TRUE(verify_sp_enote_send_proof_v1(out_proof,enotes,single_tx,eph_index));
//             EXPECT_TRUE(verify_sp_enote_send_proof_v1(out_proof_recovered,enotes,single_tx,eph_index));
//         }
//     }


// }
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_knowledge_proofs, sp_ownership_proof)
{
    //// demo of sending and receiving SpTxTypeSquashedV1 transactions (WIP)

    /// config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    // const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator for now (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    /// mock ledger context for this test
    MockLedgerContext ledger_context{0, 10000};


    /// prepare for membership proofs

    // // a. add enough fake enotes to the ledger so we can reliably make legacy ring signatures
    // std::vector<rct::xmr_amount> fake_legacy_enote_amounts(static_cast<std::size_t>(legacy_ring_size), 0);
    // const rct::key fake_legacy_spendkey{rct::pkGen()};
    // const rct::key fake_legacy_viewkey{rct::pkGen()};

    // send_legacy_coinbase_amounts_to_user(fake_legacy_enote_amounts,
    //     fake_legacy_spendkey,
    //     fake_legacy_viewkey,
    //     ledger_context);

    // b. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
            static_cast<std::size_t>(compute_bin_width(bin_config.m_bin_radius)),
            0
        );
    JamtisDestinationV1 fake_destination;
    fake_destination = gen_jamtis_destination_v1();

    send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);


    /// make two users

    // a. user keys
    legacy_mock_keys legacy_user_keys_A;
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_legacy_mock_keys(legacy_user_keys_A);
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // b. legacy user address
    rct::key legacy_subaddr_spendkey_A;
    rct::key legacy_subaddr_viewkey_A;
    cryptonote::subaddress_index legacy_subaddr_index_A;
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map_A;

    gen_legacy_subaddress(legacy_user_keys_A.Ks,
        legacy_user_keys_A.k_v,
        legacy_subaddr_spendkey_A,
        legacy_subaddr_viewkey_A,
        legacy_subaddr_index_A);

    legacy_subaddress_map_A[legacy_subaddr_spendkey_A] = legacy_subaddr_index_A;

    // c. seraphis user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);

    // d. user enote stores (refresh height = 0; seraphis initial block = 0; default spendable age = 0)
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};

    // e. user input selectors
    const InputSelectorMockV1 input_selector_A{enote_store_A};
    const InputSelectorMockV1 input_selector_B{enote_store_B};


    /// initial funding for user A: legacy 4000000 + seraphis 4000000
    // send_legacy_coinbase_amounts_to_user(
    //         {1000000, 1000000, 1000000, 1000000},
    //         legacy_subaddr_spendkey_A,
    //         legacy_subaddr_viewkey_A,
    //         ledger_context
    //     );
    send_sp_coinbase_amounts_to_user({1000000,1000000,1000000}, destination_A, ledger_context);


    /// send funds back and forth between users

    // A -> B: 6000000
    refresh_user_enote_store_legacy_full(legacy_user_keys_A.Ks,
        legacy_subaddress_map_A,
        legacy_user_keys_A.k_s,
        legacy_user_keys_A.k_v,
        refresh_config,
        ledger_context,
        enote_store_A);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) >= 3000000);
    

    std::cout << "A Balance before tx: "<< enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;

    std::cout << "B Balance before tx: "<< enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;

    // make one tx
    // The wallet should save the successful/sent payment proposals to store the ephemeral_privkeys
    // Enote record contains the input_context.
    SpTxSquashedV1 single_tx;
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payments;
    rct::key input_context;
    rct::xmr_amount amount_to_send = 2000000;
    construct_tx_for_mock_ledger_v1(legacy_mock_keys{},
        user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{amount_to_send, destination_B, TxExtra{}}},
        2,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        single_tx);

    make_standard_input_context_v1(single_tx.m_legacy_input_images,single_tx.m_sp_input_images,input_context);


    // validate and submit to the mock ledger
    const TxValidationContextMock tx_validation_context{ledger_context};

    CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
        "transfer funds single mock: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context),
        "transfer funds single mock: adding tx to mock ledger failed.");

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);
    
    std::cout << "A Balance after tx: "<< enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;
    std::cout << "B Balance after tx: "<< enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) << std::endl ;


    //Start SpEnoteOwnershipProof
    //Provide index of jamtis_proposal payment which the proof will be based on
    size_t i_payment{0};

    // jamtis::JamtisPaymentProposalV1 payment_proposal{destination_B,amount_to_send,normal_payments[i_payment].m_enote_ephemeral_privkey,{}};
    // SpOutputProposalV1 output_proposal;

    //convert payment proposal to SpOutputProposalV1
    // jamtis::get_output_proposal_v1(payment_proposal, input_context, output_proposal);
    
    //One should provide the exact enote that matches the outproof
    //A simple scanning is done to find if the enote being proved is part of the tx
    
    SpEnoteRecordV1 single_enote_record;
    for (SpEnoteV1 enote : single_tx.m_outputs)
    {
        // if (enote.m_core.m_onetime_address == output_proposal.m_core.m_onetime_address)
        // {
            try_get_enote_record_v1(enote,
            single_tx.m_tx_supplement.m_output_enote_ephemeral_pubkeys[i_payment],
            input_context,
            user_keys_B.K_1_base,
            user_keys_B.k_vb,
            single_enote_record);

            //enote.m_core.m_onetime_address //Ko
            //user_keys_B.K_1_base //K_1
            
            //single_enote_record.m_enote_ephemeral_pubkey
            //
            // single_enote_record.

            // 3. derived key: xK_d = xr * xK_2 = xkfr * xK_e
            crypto::x25519_pubkey xK_d;
            crypto::x25519_scmul_key(user_keys_B.xk_fr, single_enote_record.m_enote_ephemeral_pubkey, xK_d);
            
            rct::key q;
            make_jamtis_sender_receiver_secret_plain(xK_d, single_enote_record.m_enote_ephemeral_pubkey, input_context, q);
            
            EnoteOwnershipProofV1 proof{generate_knowledge_proof_enote_ownership_v1(q, destination_B.m_addr_K1, enote.m_core.m_onetime_address)};

            verify_knowledge_proof_enote_ownership_v1(proof,enote);


            std::cout<< "Inside loop" << std::endl;
            
            // //Generate SpOwnershipProof in that enote
            // SpKnowledgeProofEnoteOwnershipV1 in_proof{generate_sp_enote_ownership_proof_v1(single_enote_record,enote,user_keys_B.k_vb,user_keys_B.k_m)};

            // std::string in_proof_string{serialize_sp_enote_ownership_proof_v1(in_proof)};
            // SpKnowledgeProofEnoteOwnershipV1 in_proof_recovered{deserialize_sp_enote_ownership_proof_v1(in_proof_string)};

            // EXPECT_TRUE(verify_sp_enote_ownership_proof_v1(in_proof, enote));
            // EXPECT_TRUE(verify_sp_enote_ownership_proof_v1(in_proof_recovered, enote));
        // }
    }




}
//-------------------------------------------------------------------------------------------------------------------