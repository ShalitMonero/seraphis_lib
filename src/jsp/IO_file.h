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
 * \file IO_file.h
 *
 * \brief Header file that declares IO_file class.
 */

#pragma once

#include "cryptonote_basic/account.h"
#include "cryptonote_config.h"
#include <cstdint>
#include <memory>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <string>
#if BOOST_VERSION >= 107400
#include <boost/serialization/library_version_type.hpp>
#endif
#include <atomic>
#include <boost/serialization/deque.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/thread/lock_guard.hpp>
#include <random>

#include "include_base_utils.h"
#include "seraphis/jamtis_account.h"
//#include "cryptonote_basic/account.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "net/http.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/http_abstract_invoke.h"

#include "common/apply_permutation.h"
#include "common/base58.h"
#include "common/combinator.h"
#include "common/command_line.h"
#include "common/i18n.h"
#include "common/scoped_message_writer.h"
#include "common/util.h"
#include "console_handler.h"
#include "include_base_utils.h"
#include <boost/filesystem.hpp>

#include "checkpoints/checkpoints.h"
#include "common/unordered_containers_boost_serialization.h"
#include "common/util.h"
#include "crypto/chacha.h"
#include "crypto/hash.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/pair.h"
#include "serialization/string.h"

#include "common/password.h"

namespace jsw {

class IO_file {
private:
  sp::jamtis::account_base
      m_account; // Class that stores the private/public keys in memory
  cryptonote::account_base m_account_w2;

public:
  struct keys_file_data {
    crypto::chacha_iv iv;
    std::string account_data;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(iv)
    FIELD(account_data)
    END_SERIALIZE()
  };

  enum AskPasswordType {
    AskPasswordNever = 0,
    AskPasswordOnAction = 1,
    AskPasswordToDecrypt = 2,
  };

  // public variables
  uint64_t m_kdf_rounds = 1;
  bool m_is_wallet3;
  std::string m_keys_file;
  std::string m_wallet_file;

  // wallet2 functions
  AskPasswordType m_ask_password;
  bool m_unattended;
  bool m_watch_only; /*!< no spend key */
  bool m_multisig;
  std::unique_ptr<tools::file_locker> m_keys_file_locker;

  // Methods

  void generate_keys();
  std::string get_public_address_w2();
  std::string get_public_address_w3();
  // sp::jamtis::account_base get_account() {return m_account;}

  /**
   * read the command line
   * @param prompt the string being read
   * @param yesno Should I write Yes/No confirmation?
   */
  std::string input_line(const std::string &prompt, bool yesno);

  /**
   * password prompter...
   */
  boost::optional<tools::password_container>
  default_password_prompter(bool verify);

  /**
   * password prompter...
   */
  boost::optional<tools::password_container>
  password_prompter(const char *prompt, bool verify);

  /**
   * Variation of scoped_message_writer...
   */
  tools::scoped_message_writer
  message_writer(epee::console_colors color = epee::console_color_default,
                 bool bright = false);

  /**
   * Prepare wallet filename by adding .keys if necessary
   */
  void do_prepare_file_names(const std::string &file_path,
                             std::string &keys_file, std::string &wallet_file);

  /**
   * Prepare wallet filename by storing at m_keys_file and m_wallet_file
   */
  bool prepare_file_names(const std::string &file_path);

  /**
   * Verify if the wallet exists
   */
  void wallet_exists(const std::string &file_path, bool &keys_file_exists,
                     bool &wallet_file_exists);

  /**
   * Verify if the wallet path is valid
   */
  bool wallet_valid_path_format(const std::string &file_path);

  /**
   * Prepare the necessary info to save wallet to disk
   */
  boost::optional<IO_file::keys_file_data>
  get_keys_file_data(const epee::wipeable_string &password, bool watch_only);

  /**
   * Prepare the necessary info to save wallet to disk
   */
  bool save_to_file(const std::string &path_to_file, const std::string &raw,
                    bool is_printable);

  /**
   * Prepare the necessary info to save wallet to disk
   */
  bool store_keys(const std::string &keys_file_name,
                  const epee::wipeable_string &password, bool watch_only);

  /**
   * Prepare the necessary info to load wallet from disk
   */
  bool load_keys_buf_w3(const std::string &keys_buf,
                        const epee::wipeable_string &password,
                        boost::optional<crypto::chacha_key> &keys_to_encrypt);

  /**
   * Prepare the necessary info to load wallet from disk
   */
  bool load_keys_w3(const std::string &keys_file_name,
                    const epee::wipeable_string &password);

  /**
   * Prepare the necessary info to load wallet from disk
   */
  bool load_from_file(const std::string &path_to_file, std::string &target_str,
                      size_t max_size=1000000000);

  void setup_keys(const epee::wipeable_string &password);

  /**
   * Encrypt keys in memory
   */
  void encrypt_keys(const crypto::chacha_key &key);

  /**
   * Decrypt keys from memory
   */
  void decrypt_keys(const crypto::chacha_key &key);

  /**
   * Encrypt keys in memory
   */
  void encrypt_keys(const epee::wipeable_string &password);

  /**
   * Decrypt keys from memory
   */
  void decrypt_keys(const epee::wipeable_string &password);

  // Wallet2 functions

  bool load_keys_w2(const std::string &keys_file_name,
                    const epee::wipeable_string &password);

  bool load_keys_buf_w2(const std::string &keys_buf,
                        const epee::wipeable_string &password);

  bool load_keys_buf_w2(const std::string &keys_buf,
                        const epee::wipeable_string &password,
                        boost::optional<crypto::chacha_key> &keys_to_encrypt);
};
} // namespace jsw
