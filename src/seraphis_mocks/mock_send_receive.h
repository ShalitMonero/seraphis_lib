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

// Seraphis tx-builder/component-builder mockups (tx inputs).


#pragma once

//local headers
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "jamtis_mock_keys.h"
#include "legacy_mock_keys.h"
#include "mock_ledger_context.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_enote_scanning.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_fee_calculator.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/txtype_coinbase_v1.h"
#include "seraphis/txtype_squashed_v1.h"
#include "tx_enote_store_mocks.h"

//third party headers

//standard headers
#include <tuple>
#include <unordered_map>
#include <vector>

//forward declarations


namespace sp
{

//todo
void convert_outlay_to_payment_proposal(const rct::xmr_amount outlay_amount,
    const jamtis::JamtisDestinationV1 &destination,
    const TxExtra &partial_memo_for_destination,
    jamtis::JamtisPaymentProposalV1 &payment_proposal_out);
void send_legacy_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
    const rct::key &destination_subaddr_spend_pubkey,
    const rct::key &destination_subaddr_view_pubkey,
    MockLedgerContext &ledger_context_inout);
void send_sp_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
    const jamtis::JamtisDestinationV1 &user_address,
    MockLedgerContext &ledger_context_inout);
void send_sp_coinbase_amounts_to_users(const std::vector<std::vector<rct::xmr_amount>> &coinbase_amounts_per_user,
    const std::vector<jamtis::JamtisDestinationV1> &user_addresses,
    MockLedgerContext &ledger_context_inout);
//todo
void construct_tx_for_mock_ledger_v1(const legacy_mock_keys &local_user_legacy_keys,
    const jamtis::jamtis_mock_keys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, jamtis::JamtisDestinationV1, TxExtra>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout,
    SpTxSquashedV1 &tx_out);
void transfer_funds_single_mock_v1_unconfirmed_sp_only(const jamtis::jamtis_mock_keys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, jamtis::JamtisDestinationV1, TxExtra>> &outlays,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout);
void transfer_funds_single_mock_v1_unconfirmed(const legacy_mock_keys &local_user_legacy_keys,
    const jamtis::jamtis_mock_keys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, jamtis::JamtisDestinationV1, TxExtra>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout);
void transfer_funds_single_mock_v1(const legacy_mock_keys &local_user_legacy_keys,
    const jamtis::jamtis_mock_keys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, jamtis::JamtisDestinationV1, TxExtra>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    MockLedgerContext &ledger_context_inout);
//todo
void refresh_user_enote_store(const jamtis::jamtis_mock_keys &user_keys,
    const RefreshLedgerEnoteStoreConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    SpEnoteStoreMockV1 &user_enote_store_inout);
void refresh_user_enote_store_PV(const jamtis::jamtis_mock_keys &user_keys,
    const RefreshLedgerEnoteStoreConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    SpEnoteStoreMockPaymentValidatorV1 &user_enote_store_inout);
void refresh_user_enote_store_legacy_full(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const RefreshLedgerEnoteStoreConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    SpEnoteStoreMockV1 &user_enote_store_inout);
void refresh_user_enote_store_legacy_intermediate(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const LegacyScanMode legacy_scan_mode,
    const RefreshLedgerEnoteStoreConfig &refresh_config,
    const MockLedgerContext &ledger_context,
    SpEnoteStoreMockV1 &user_enote_store_inout);

} //namespace sp