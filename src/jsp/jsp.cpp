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

/*!
 * \file simplewallet.cpp
 *
 * \brief Source file that defines seraphis_simplewallet class.
 */

#include "jsp.h"
#include "wallet/wallet2.h"
#include <boost/algorithm/string.hpp>
#include <memory>

#include "cryptonote_config.h"

using namespace epee;
using namespace std;
using namespace jsw;

#define EXTENDED_LOGS_FILE "wallet_details.log"

int main(int argc, char *argv[]) {
  jsw_driver w;
  w.init();
  return 1;
}

bool jsw_driver::init() {
  if (create_or_open_wallet())
    return false;
  return true;
}

bool jsw_driver::create_or_open_wallet() {
  LOG_PRINT_L3("Basic wallet creation");

  std::string wallet_path;
  std::string confirm_creation;
  std::string confirm_password;

  bool keys_file_exists = false;
  bool wallet_file_exists = false;
  bool wallet_name_valid = false;

  IO_file fh;

  do {
    LOG_PRINT_L3("User asked to specify wallet file name.");
    wallet_path = fh.input_line(
        "Specify a new wallet file name for your Jamtis/Seraphis wallet (e.g., "
        "MyWallet).\nWallet file name (or Ctrl-C to quit)",
        false);
    if (std::cin.eof()) {
      LOG_ERROR("Unexpected std::cin.eof() - Exited seraphis_create_basic::");
      return false;
    }
    m_w3.m_file.wallet_exists(wallet_path, keys_file_exists,
                              wallet_file_exists);
    if (keys_file_exists) {
      // Wallet found -> need to be loaded
      tools::success_msg_writer() << tr("Wallet found");
      auto pw = fh.password_prompter(tr("Enter your wallet password"), false);

      try {
        m_w3.m_file.prepare_file_names(wallet_path);
        m_w3.m_file.load_keys_w3(m_w3.m_file.m_keys_file, pw->password());
        if (m_w3.m_file.m_is_wallet3 == false) {
          // if it is not wallet3 then load wallet2
          cout << "Loading wallet2" << endl;


          // m_w2.m_file.prepare_file_names(wallet_path);
          // m_w2.m_file.load_keys_w2(wallet_path, pw->password());
          // cout << "Address of wallet2 loaded: "
          //      << m_w2.m_file.get_public_address_w2() << endl;


          tools::wallet2 *w2 = new tools::wallet2;
          w2->load(wallet_path,pw->password());
          cout << "Address wallet2 loaded: " << w2->get_address_as_str() << endl;
        } else {
          // wallet3 loaded
          std::cout << m_w3.m_file.get_public_address_w3() << std::endl;
        }
      } catch (...) {
      }

      wallet_name_valid = true;
    } else {
      bool ok = true;
      fh.message_writer() << tr("No wallet found with that name. Confirm "
                                "creation of new wallet named: ")
                          << wallet_path;
      confirm_creation = fh.input_line("", true);
      if (std::cin.eof()) {
        LOG_ERROR("Unexpected std::cin.eof() - Exited "
                  "simple_wallet::ask_wallet_create_if_needed()");
        return false;
      }
      ok = command_line::is_yes(confirm_creation);
      if (ok) {
        tools::success_msg_writer() << tr("Generating new wallet...");
        auto pw = fh.password_prompter(
            tr("Enter a new password for the wallet"), false);

        create_new_keys_w3(wallet_path, pw->password());

        wallet_name_valid = true;
      }
    }
  } while (!wallet_name_valid);

  LOG_ERROR("Failed out of do-while loop in ask_wallet_create_if_needed()");
  return false;
}

void jsw_driver::create_new_keys_w3(std::string &wallet_path,
                                    const epee::wipeable_string &password) {
  m_w3.m_file.m_is_wallet3 = true;
  m_w3.m_file.generate_keys();
  m_w3.m_file.prepare_file_names(wallet_path);
  m_w3.m_file.store_keys(m_w3.m_file.m_keys_file, password, false);
}