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
#include "tx_enote_record_types.h"
#include "tx_enote_store.h"
#include "tx_input_selection.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <list>

//forward declarations


namespace sp
{

/// simple input selector: select the next available input in the enote store (input selection with this is not thread-safe)
class InputSelectorMockSimpleV1 final : public InputSelectorV1
{
public:
//constructors
    /// normal constructor
    InputSelectorMockSimpleV1(const SpEnoteStoreV1 &enote_store) :
        m_enote_store{enote_store}
    {
        // in practice, lock the enote store with an 'input selection' mutex here for thread-safe input selection that
        //   prevents two tx attempts from using the same inputs (take a reader-writer lock when selecting an input)
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    InputSelectorMockSimpleV1& operator=(InputSelectorMockSimpleV1&&) = delete;

//member functions
    /// select the next available input
    bool try_select_input_v1(const boost::multiprecision::uint128_t desired_total_amount,
        const std::list<SpContextualEnoteRecordV1> &already_added_inputs,
        const std::list<SpContextualEnoteRecordV1> &already_excluded_inputs,
        SpContextualEnoteRecordV1 &selected_input_out) const override
    {
        for (const SpContextualEnoteRecordV1 &contextual_enote_record : m_enote_store.m_contextual_enote_records)
        {
            // find the next enote record that hasn't already been selected (via onetime address comparisons)
            auto record_finder =
                [&contextual_enote_record](const SpContextualEnoteRecordV1 &comparison_record) -> bool
                {
                    return SpContextualEnoteRecordV1::same_destination(contextual_enote_record, comparison_record);
                };

            if (std::find_if(already_added_inputs.begin(), already_added_inputs.end(), record_finder) ==
                    already_added_inputs.end()
                &&
                std::find_if(already_excluded_inputs.begin(), already_excluded_inputs.end(), record_finder) ==
                    already_excluded_inputs.end())
            {
                selected_input_out = contextual_enote_record;
                return true;
            }
        }

        return false;
    }

//member variables
private:
    /// read-only reference to an enote storage
    const SpEnoteStoreV1 &m_enote_store;
};

} //namespace sp
