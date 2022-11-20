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
 * \brief Header file that declares simple_wallet class.
 */
// paired header
#include "IO_file.h"

// local headers

// third party headers
#include <boost/algorithm/string.hpp>

// standard headers
#include <iostream>

#ifdef WIN32
#include <boost/filesystem.hpp>
#include <boost/locale.hpp>
#include <fcntl.h>
#endif

#ifdef HAVE_READLINE
#include "readline_buffer.h"
#endif

#include "common/apply_permutation.h"
#include "common/combinator.h"
#include "common/command_line.h"
#include "common/i18n.h"
#include "common/scoped_message_writer.h"
#include "common/util.h"
#include "console_handler.h"
#include "include_base_utils.h"
#include <boost/filesystem.hpp>

#include "common/json_util.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "serialization/json_object.h"

#include "cryptonote_basic/account_boost_serialization.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "seraphis/jamtis_account.h"

#include "mnemonics/electrum-words.h"

#include "memwipe.h"

#include "common/boost_serialization_helper.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"

#include "common/password.h"

extern "C" {
#include "crypto/crypto-ops.h"
#include "crypto/keccak.h"
}

using namespace epee;

#define PRINT_USAGE(usage_help)                                                \
  fail_msg_writer() << boost::format(tr("usage: %s")) % usage_help;

static const std::string ASCII_OUTPUT_MAGIC = "MoneroAsciiDataV1";

namespace jsw {

std::string IO_file::input_line(const std::string &prompt, bool yesno) {
  PAUSE_READLINE();
  std::cout << prompt;
  if (yesno)
    std::cout << "  (Y/Yes/N/No)";
  std::cout << ": " << std::flush;

  std::string buf;
#ifdef _WIN32
  buf = tools::input_line_win();
#else
  std::getline(std::cin, buf);
#endif

  return epee::string_tools::trim(buf);
}

tools::scoped_message_writer IO_file::message_writer(epee::console_colors color,
                                                     bool bright) {
  return tools::scoped_message_writer(color, bright);
}

boost::optional<tools::password_container>
IO_file::password_prompter(const char *prompt, bool verify) {
  PAUSE_READLINE();
  auto pwd_container = tools::password_container::prompt(verify, prompt);
  if (!pwd_container) {
    tools::fail_msg_writer() << tr("failed to read wallet password");
  }
  return pwd_container;
}

boost::optional<tools::password_container>
IO_file::default_password_prompter(bool verify) {
  return password_prompter(verify ? tr("Enter a new password for the wallet")
                                  : tr("Wallet password"),
                           verify);
}

bool IO_file::wallet_valid_path_format(const std::string &file_path) {
  return !file_path.empty();
}

// generate keys
void IO_file::generate_keys() { m_account.generate(); }

// save wallet file...

boost::optional<IO_file::keys_file_data>
IO_file::get_keys_file_data(const epee::wipeable_string &password,
                            bool watch_only) {
  epee::byte_slice account_data;
  std::string multisig_signers;
  std::string multisig_derivations;
  // cryptonote::account_base account = m_account;
  sp::jamtis::account_base account = m_account;

  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);

  // account.encrypt_viewkey(key);
  // account.decrypt_keys(key);

  // if (watch_only)
  // account.forget_spend_key();

  // account.encrypt_keys(key);

  bool r = epee::serialization::store_t_to_binary(account, account_data);
  CHECK_AND_ASSERT_MES(r, boost::none, "failed to serialize wallet keys");
  boost::optional<IO_file::keys_file_data> keys_file_data =
      (IO_file::keys_file_data){};

  // Create a JSON object with "key_data" and "seed_language" as keys.
  rapidjson::Document json;
  json.SetObject();
  rapidjson::Value value(rapidjson::kStringType);
  value.SetString(reinterpret_cast<const char *>(account_data.data()),
                  account_data.size());
  json.AddMember("key_data", value, json.GetAllocator());

  rapidjson::Value value2(rapidjson::kNumberType);
  value2.SetInt(m_is_wallet3 ? 1 : 0);
  json.AddMember("is_wallet3", value2, json.GetAllocator());

  // Serialize the JSON object
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  json.Accept(writer);

  // Encrypt the entire JSON object.
  std::string cipher;
  cipher.resize(buffer.GetSize());
  keys_file_data.get().iv = crypto::rand<crypto::chacha_iv>();
  crypto::chacha20(buffer.GetString(), buffer.GetSize(), key,
                   keys_file_data.get().iv, &cipher[0]);
  keys_file_data.get().account_data = cipher;
  return keys_file_data;
}

bool IO_file::save_to_file(const std::string &path_to_file,
                           const std::string &raw, bool is_printable) {
  FILE *fp = fopen(path_to_file.c_str(), "w+");
  if (!fp) {
    MERROR("Failed to open wallet file for writing: " << path_to_file << ": "
                                                      << strerror(errno));
    return false;
  }

  // Save the result b/c we need to close the fp before returning
  // success/failure.
  int write_result =
      PEM_write(fp, ASCII_OUTPUT_MAGIC.c_str(), "",
                (const unsigned char *)raw.c_str(), raw.length());
  fclose(fp);

  if (write_result == 0) {
    return false;
  } else {
    return true;
  }
}

bool IO_file::store_keys(const std::string &keys_file_name,
                         const epee::wipeable_string &password,
                         bool watch_only) {

  boost::optional<IO_file::keys_file_data> keys_file_data =
      get_keys_file_data(password, watch_only);
  CHECK_AND_ASSERT_MES(keys_file_data != boost::none, false,
                       "failed to generate wallet keys data");

  std::string tmp_file_name = keys_file_name + ".new";
  std::string buf;
  bool r = ::serialization::dump_binary(keys_file_data.get(), buf);
  r = r && save_to_file(tmp_file_name, buf, true);
  CHECK_AND_ASSERT_MES(r, false,
                       "failed to generate wallet keys file " << tmp_file_name);

  std::error_code e = tools::replace_file(tmp_file_name, keys_file_name);

  if (e) {
    boost::filesystem::remove(tmp_file_name);
    LOG_ERROR("failed to update wallet keys file " << keys_file_name);
    return false;
  }

  return true;
}

bool IO_file::prepare_file_names(const std::string &file_path) {
  do_prepare_file_names(file_path, m_keys_file, m_wallet_file);
  return true;
}

void IO_file::do_prepare_file_names(const std::string &file_path,
                                    std::string &keys_file,
                                    std::string &wallet_file) {
  keys_file = file_path;
  wallet_file = file_path;
  if (string_tools::get_extension(keys_file) ==
      "keys") { // provided keys file name
    wallet_file = string_tools::cut_off_extension(wallet_file);
  } else { // provided wallet file name
    keys_file += ".keys";
  }
}

void IO_file::wallet_exists(const std::string &file_path,
                            bool &keys_file_exists, bool &wallet_file_exists) {
  std::string keys_file, wallet_file;
  do_prepare_file_names(file_path, keys_file, wallet_file);

  boost::system::error_code ignore;
  keys_file_exists = boost::filesystem::exists(keys_file, ignore);
  wallet_file_exists = boost::filesystem::exists(wallet_file, ignore);
}

// load keys...
bool IO_file::load_keys_buf_w3(
    const std::string &keys_buf, const epee::wipeable_string &password,
    boost::optional<crypto::chacha_key> &keys_to_encrypt) {

  // Decrypt the contents
  rapidjson::Document json;
  IO_file::keys_file_data keys_file_data;
  bool encrypted_secret_keys = false;
  bool r = ::serialization::parse_binary(keys_buf, keys_file_data);
  // THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal
  // error: failed to deserialize keys buffer");
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(),
                   keys_file_data.account_data.size(), key, keys_file_data.iv,
                   &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject()) {
    // printf("inside this if");
    crypto::chacha8(keys_file_data.account_data.data(),
                    keys_file_data.account_data.size(), key, keys_file_data.iv,
                    &account_data[0]);
  }
  // The contents should be JSON if the wallet follows the new format.
  if (json.IsObject()) {
    if (!json.HasMember("key_data")) {
      // printf("\nInside key_data\n");
      LOG_ERROR("Field key_data not found in JSON");
      return false;
    }
    if (!json["key_data"].IsString()) {
      // printf("\nInside key_data string\n");
      LOG_ERROR("Field key_data found in JSON, but not String");
      return false;
    }

    account_data = std::string(json["key_data"].GetString(),
                               json["key_data"].GetString() +
                                   json["key_data"].GetStringLength());
  }

  r = epee::serialization::load_t_from_binary(m_account, account_data);
  // THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);

  GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, is_wallet3, int, Int, false, false);
  m_is_wallet3 = field_is_wallet3;

  if (r) {
    if (encrypted_secret_keys) {
      m_account.decrypt_keys(key);
    } else {
      keys_to_encrypt = key;
    }
  }

  // if (r)
  // setup_keys(password);

  return true;
}

bool IO_file::load_from_file(const std::string &path_to_file,
                             std::string &target_str, size_t max_size) {
  std::string data;
  bool r =
      epee::file_io_utils::load_file_to_string(path_to_file, data, max_size);
  if (!r) {
    return false;
  }

  if (!boost::algorithm::contains(
          boost::make_iterator_range(data.begin(), data.end()),
          ASCII_OUTPUT_MAGIC)) {
    // It's NOT our ascii dump.
    target_str = std::move(data);
    return true;
  }

  // Creating a BIO and calling PEM_read_bio instead of simpler PEM_read
  // to avoid reading the file from disk twice.
  BIO *b = BIO_new_mem_buf((const void *)data.data(), data.length());

  char *name = NULL;
  char *header = NULL;
  unsigned char *openssl_data = NULL;
  long len = 0;

  // Save the result b/c we need to free the data before returning
  // success/failure.
  int success = PEM_read_bio(b, &name, &header, &openssl_data, &len);

  try {
    target_str = std::string((const char *)openssl_data, len);
  } catch (...) {
    success = 0;
  }

  OPENSSL_free((void *)name);
  OPENSSL_free((void *)header);
  OPENSSL_free((void *)openssl_data);
  BIO_free(b);

  if (success == 0) {
    return false;
  } else {
    return true;
  }
}

//----------------------------------------------------------------------------------------------------
bool IO_file::load_keys_w3(const std::string &keys_file_name,
                           const epee::wipeable_string &password) {
  std::string keys_file_buf;
  bool r = load_from_file(keys_file_name, keys_file_buf);

  // Load keys from buffer
  boost::optional<crypto::chacha_key> keys_to_encrypt;
  r = load_keys_buf_w3(keys_file_buf, password, keys_to_encrypt);

  return r;
}
//----------------------------------------------------------------------------------------------------

void IO_file::setup_keys(const epee::wipeable_string &password) {
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);

  // re-encrypt, but keep viewkey unencrypted
  m_account.encrypt_keys(key);
  m_account.decrypt_viewkey(key);

  m_account_w2.encrypt_keys(key);
  m_account_w2.decrypt_viewkey(key);
}

void IO_file::encrypt_keys(const crypto::chacha_key &key) {
  m_account.encrypt_keys(key);
  m_account.decrypt_viewkey(key);
}

void IO_file::decrypt_keys(const crypto::chacha_key &key) {
  m_account.encrypt_viewkey(key);
  m_account.decrypt_keys(key);
}

void IO_file::encrypt_keys(const epee::wipeable_string &password) {
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);
  encrypt_keys(key);
}

void IO_file::decrypt_keys(const epee::wipeable_string &password) {
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);
  decrypt_keys(key);
}

std::string IO_file::get_public_address_w3() {
  return m_account.get_public_address_str();
}
// Wallet2 functions

std::string IO_file::get_public_address_w2() {
  return m_account_w2.get_public_address_str(cryptonote::MAINNET);
}

bool IO_file::load_keys_w2(const std::string &keys_file_name,
                           const epee::wipeable_string &password) {
  std::string keys_file_buf;
  bool r = load_from_file(keys_file_name, keys_file_buf);

  // Load keys from buffer
  boost::optional<crypto::chacha_key> keys_to_encrypt;
  r = IO_file::load_keys_buf_w2(keys_file_buf, password, keys_to_encrypt);

  // Rewrite with encrypted keys if unencrypted, ignore errors
  // if (r && keys_to_encrypt != boost::none) {
  //   if (m_ask_password == AskPasswordToDecrypt && !m_unattended &&
  //       !m_watch_only)
  //     encrypt_keys(keys_to_encrypt.get());
  //   bool saved_ret = store_keys(keys_file_name, password, m_watch_only);
  //   if (!saved_ret) {
  //     // just moan a bit, but not fatal
  //     MERROR("Error saving keys file with encrypted keys, not fatal");
  //   }
  //   if (m_ask_password == AskPasswordToDecrypt && !m_unattended &&
  //       !m_watch_only)
  //     decrypt_keys(keys_to_encrypt.get());
  //   m_keys_file_locker.reset();
  // }
  return r;
}
//----------------------------------------------------------------------------------------------------
bool IO_file::load_keys_buf_w2(const std::string &keys_buf,
                               const epee::wipeable_string &password) {
  boost::optional<crypto::chacha_key> keys_to_encrypt;
  return IO_file::load_keys_buf_w2(keys_buf, password, keys_to_encrypt);
}
//----------------------------------------------------------------------------------------------------
bool IO_file::load_keys_buf_w2(
    const std::string &keys_buf, const epee::wipeable_string &password,
    boost::optional<crypto::chacha_key> &keys_to_encrypt) {

  // Decrypt the contents
  rapidjson::Document json;
  IO_file::keys_file_data keys_file_data;
  bool encrypted_secret_keys = false;
  bool r = ::serialization::parse_binary(keys_buf, keys_file_data);

  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);
  std::string account_data;
  account_data.resize(keys_file_data.account_data.size());
  crypto::chacha20(keys_file_data.account_data.data(),
                   keys_file_data.account_data.size(), key, keys_file_data.iv,
                   &account_data[0]);
  if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    crypto::chacha8(keys_file_data.account_data.data(),
                    keys_file_data.account_data.size(), key, keys_file_data.iv,
                    &account_data[0]);
  // The contents should be JSON if the wallet follows the new format.
  if (json.Parse(account_data.c_str()).HasParseError()) {
    m_watch_only = false;
    m_multisig = false;
    m_ask_password = AskPasswordToDecrypt;
    encrypted_secret_keys = false;
  } else if (json.IsObject()) {
    if (!json.HasMember("key_data")) {
      LOG_ERROR("Field key_data not found in JSON");
      return false;
    }
    if (!json["key_data"].IsString()) {
      LOG_ERROR("Field key_data found in JSON, but not String");
      return false;
    }
    const char *field_key_data = json["key_data"].GetString();
    account_data = std::string(
        field_key_data, field_key_data + json["key_data"].GetStringLength());

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, watch_only, int, Int, false,
                                        false);
    m_watch_only = field_watch_only;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, multisig, int, Int, false, false);
    m_multisig = field_multisig;
    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, ask_password, AskPasswordType,
                                        Int, false, AskPasswordToDecrypt);
    m_ask_password = field_ask_password;
  }

  r = epee::serialization::load_t_from_binary(m_account_w2, account_data);

  // if (r) {
  //   if (encrypted_secret_keys) {
  //     m_account_w2.decrypt_keys(key);
  //   } else {
  //     keys_to_encrypt = key;
  //   }
  // }

  // if (r)
  //   setup_keys(password);

  return true;
}

} // namespace jsw
