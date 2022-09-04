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

// Utilities for selecting tx inputs from an enote storage.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_contextual_enote_record_types.h"
#include "tx_fee_calculator.h"
#include "tx_input_selection_output_context.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <list>
#include <vector>

//forward declarations


namespace sp
{

class InputSelectorV1
{
public:
//constructors: default
//destructor
    virtual ~InputSelectorV1() = default;

//overloaded operators
    /// disable copy/move (this is a pure virtual base class)
    InputSelectorV1& operator=(InputSelectorV1&&) = delete;

//member functions
    /// select an available input
    virtual bool try_select_input_v1(const boost::multiprecision::uint128_t desired_total_amount,
        const std::list<ContextualRecordVariant> &already_added_inputs,
        const std::list<ContextualRecordVariant> &already_excluded_inputs,
        ContextualRecordVariant &selected_input_out) const = 0;
};

//todo
/*
    - note: this algorithm will fail to find a possible solution if there are combinations that lead to 0-change successes,
      but the combination that was found has non-zero change that doesn't cover the differential fee of adding a change
      output (and there are no solutions that can cover that additional change output differential fee)
        - only a brute force search can find the success solution(s) to this problem (e.g. if step (4) fails, you could
          fall-back to brute force search on the 0-change case; however, such cases will be extremely rare if they ever
          actually occur, so it probably isn't worthwhile to implement)
*/
bool try_get_input_set_v1(const OutputSetContextForInputSelection &output_set_context,
    const std::size_t max_inputs_allowed,
    const InputSelectorV1 &input_selector,
    const rct::xmr_amount fee_per_tx_weight,
    const FeeCalculator &tx_fee_calculator,
    rct::xmr_amount &final_fee_out,
    std::list<ContextualRecordVariant> &contextual_enote_records_out);

} //namespace sp
