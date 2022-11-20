// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list
//    of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote
// developers

/**
 * @file Wallet3 declaration
 * \brief Header file that declares Wallet3 class. This is the main wallet file.
 */

#pragma once

#include "wallets.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.jsp"
// Hardcode Monero's donation address (see #1447)
constexpr const char MONERO_DONATION_ADDR[] =
    "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwM"
    "VgN5S9cQUiyoogDavup3H";

/**
 * jsw (Jamtis-Seraphis-Wallet)
 * Holds related classes and helpers.
 * Responsible for the program flow
 */

namespace jsw {

// class w2 : public tools::i_wallet2_callback{

// public:
// //std::unique_ptr<tools::wallet2> m_wallet;

// };

class jsw_driver {
private:
  jsw::Wallet3 m_w3;
  jsw::Wallet2_legacy m_w2;

public:
  // Constructors, destructors and others will be created...
  std::unique_ptr<jsw::Wallet2_legacy> m_ptr_wallet2;
  std::unique_ptr<jsw::Wallet3> m_ptr_wallet3;

  // jsw_driver() {
  // std::unique_ptr<jsw::Wallet2_legacy> m_wallet2(new jsw::Wallet2_legacy);
  // std::unique_ptr<jsw::Wallet3> m_wallet3 (new jsw::Wallet3);
  // }

  bool init();
  bool create_or_open_wallet();
  void create_new_keys_w3(std::string &wallet_path,
                          const epee::wipeable_string &password);
};

} // namespace jsw
