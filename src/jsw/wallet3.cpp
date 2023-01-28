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

//paired header
#include "wallet3.h"

// local headers
#include "byte_slice.h"
#include "common/command_line.h"
#include "common/i18n.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "crypto/chacha.h"
#include "key_container.h"
#include "misc_log_ex.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "common/json_util.h"
#include "storages/portable_storage_template_helper.h"
#include "string_tools.h"
#include "console_handler.h"

#include "common/boost_serialization_helper.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "serialization/json_object.h"
#include <boost/format/format_fwd.hpp>

extern "C" {
#include "crypto/crypto-ops.h"
#include "crypto/keccak.h"
}

//standard headers
#include <iostream>
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/format.hpp>
#include <limits>
#include <openssl/pem.h>
#include <string>
#include <vector>

// use boost bind placeholders for now
#define BOOST_BIND_GLOBAL_PLACEHOLDERS 1
#include <boost/bind.hpp>

using namespace jsw;
using namespace epee;
using namespace std;
using namespace sp::jamtis;


#define PRINT_USAGE(usage_help)                                                \
  fail_msg_writer() << boost::format(tr("usage: %s")) % usage_help;

static const std::string ASCII_OUTPUT_MAGIC = "MoneroAsciiDataV1";

const char* USAGE_SHOW_BALANCE("balance [detail]");
const char* USAGE_SHOW_TRANSFER("show_transfer <txid>");
const char* USAGE_SHOW_TRANSFERS("show_transfers [in|out|all|pending|failed|pool|coinbase] [index=<N1>[,<N2>,...]] [<min_height> [<max_height>]]");


int main(int argc, char *argv[]) 
{
  wallet3 my_wallet;
  my_wallet.init();
  my_wallet.run();
  return 1;
}


namespace jsw 
{
wallet3::wallet3():
m_last_activity_time(time(NULL))
{
//   m_cmd_binder.set_handler("save_bc",
//                            boost::bind(&wallet3::on_command, this, &wallet3::save_bc, _1),
//                            tr("Save the current blockchain data."));
//   m_cmd_binder.set_handler("refresh",
//                            boost::bind(&wallet3::on_command, this, &wallet3::refresh, _1),
//                            tr("Synchronize the transactions and balance."));
//   m_cmd_binder.set_handler("balance",
//                            boost::bind(&wallet3::on_command, this, &wallet3::show_balance, _1),
//                            tr(USAGE_SHOW_BALANCE),
//                            tr("Show the wallet's balance of the currently selected account."));
  m_cmd_binder.set_handler("save_watch_only",
                           boost::bind(&wallet3::on_command, this, &wallet3::save_watch_only, _1),
                           tr("Save a watch-only keys file."));
//   m_cmd_binder.set_handler("viewkey",
//                            boost::bind(&wallet3::on_command, this, &wallet3::viewkey, _1),
//                            tr("Display the private view key."));
//   m_cmd_binder.set_handler("get_tx_proof",
//                            boost::bind(&wallet3::on_command, this, &wallet3::get_tx_proof, _1),
//                            tr(USAGE_GET_TX_PROOF),
//                            tr("Generate a signature proving funds sent to <address> in <txid>, optionally with a challenge string <message>, using either the transaction secret key (when <address> is not your wallet's address) or the view secret key (otherwise), which does not disclose the secret key."));
//   m_cmd_binder.set_handler("check_tx_proof",
//                            boost::bind(&wallet3::on_command, this, &wallet3::check_tx_proof, _1),
//                            tr(USAGE_CHECK_TX_PROOF),
//                            tr("Check the proof for funds going to <address> in <txid> with the challenge string <message> if any."));
//   m_cmd_binder.set_handler("show_transfers",
//                            boost::bind(&wallet3::on_command, this, &wallet3::show_transfers, _1),
//                            tr(USAGE_SHOW_TRANSFERS),
//                            // Seemingly broken formatting to compensate for the backslash before the quotes.
//                            tr("Show the incoming/outgoing transfers within an optional height range.\n\n"
//                               "Output format:\n"
//                               "In or Coinbase:    Block Number, \"block\"|\"in\",              Time, Amount,  Transaction Hash, Payment ID, Subaddress Index,                     \"-\", Note\n"
//                               "Out:               Block Number, \"out\",                     Time, Amount*, Transaction Hash, Payment ID, Fee, Destinations, Input addresses**, \"-\", Note\n"
//                               "Pool:                            \"pool\", \"in\",              Time, Amount,  Transaction Hash, Payment Id, Subaddress Index,                     \"-\", Note, Double Spend Note\n"
//                               "Pending or Failed:               \"failed\"|\"pending\", \"out\", Time, Amount*, Transaction Hash, Payment ID, Fee, Input addresses**,               \"-\", Note\n\n"
//                               "* Excluding change and fee.\n"
//                               "** Set of address indices used as inputs in this transfer."));
  m_cmd_binder.set_unknown_command_handler(boost::bind(&wallet3::on_command, this, &wallet3::on_unknown_command, _1));
  m_cmd_binder.set_empty_command_handler(boost::bind(&wallet3::on_empty_command, this));
  m_cmd_binder.set_cancel_handler(boost::bind(&wallet3::on_cancelled_command, this));
}
//----------------------------------------------------------------------------------------------------
bool wallet3::on_unknown_command(const std::vector<std::string> &args)
{
  if (args[0] == "exit" || args[0] == "q") // backward compat
    return false;
  tools::fail_msg_writer() << boost::format(tr("Unknown command '%s', try 'help'")) % args.front();
  return true;
}

bool wallet3::on_empty_command()
{
  return true;
}

bool wallet3::on_cancelled_command()
{
  check_for_inactivity_lock(false);
  return true;
}


bool wallet3::on_command(bool (wallet3::*cmd)(const std::vector<std::string>&), const std::vector<std::string> &args)
{
  m_last_activity_time = time(NULL);

  m_in_command = true;
  epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){
    m_last_activity_time = time(NULL);
    m_in_command = false;
  });

  check_for_inactivity_lock(false);
  return (this->*cmd)(args);
}

bool wallet3::save_watch_only(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
    std::cout << "Saving watchonly" << std::endl;
  return true;
}

bool wallet3::show_transfers(const std::vector<std::string> &args_)
{
  return true;
}

void wallet3::check_for_inactivity_lock(bool user)
{
  if (m_locked)
  {
#ifdef HAVE_READLINE
    PAUSE_READLINE();
    rdln::clear_screen();
#endif
    tools::clear_screen();
    m_in_command = true;
    if (!user)
    {
      const std::string speech = tr("I locked your Monero wallet to protect you while you were away\nsee \"help set\" to configure/disable");
      std::vector<std::pair<std::string, size_t>> lines = tools::split_string_by_width(speech, 45);

      size_t max_len = 0;
      for (const auto &i: lines)
        max_len = std::max(max_len, i.second);
      const size_t n_u = max_len + 2;
      tools::msg_writer() << " " << std::string(n_u, '_');
      for (size_t i = 0; i < lines.size(); ++i)
        tools::msg_writer() << (i == 0 ? "/" : i == lines.size() - 1 ? "\\" : "|") << " " << lines[i].first << std::string(max_len - lines[i].second, ' ') << " " << (i == 0 ? "\\" : i == lines.size() - 1 ? "/" : "|");
      tools::msg_writer() << " " << std::string(n_u, '-') << std::endl <<
          "        \\   (__)" << std::endl <<
          "         \\  (oo)\\_______" << std::endl <<
          "            (__)\\       )\\/\\" << std::endl <<
          "                ||----w |" << std::endl <<
          "                ||     ||" << std::endl <<
          "" << std::endl;
    }
    while (1)
    {
      const char *inactivity_msg = user ? "" : tr("Locked due to inactivity.");
      tools::msg_writer() << inactivity_msg << (inactivity_msg[0] ? " " : "") << tr("The wallet password is required to unlock the console.");

    //   const bool show_wallet_name = m_wallet->show_wallet_name_when_locked();
    //   if (show_wallet_name)
    //   {
    //     tools::msg_writer() << tr("Filename: ") << m_wallet->get_wallet_file();
    //     tools::msg_writer() << tr("Network type: ") << (
    //       m_wallet->nettype() == cryptonote::TESTNET ? tr("Testnet") :
    //       m_wallet->nettype() == cryptonote::STAGENET ? tr("Stagenet") : tr("Mainnet")
    //     );
    //   }
      try
      {
        if (get_and_verify_password())
          break;
      }
      catch (...) { /* do nothing, just let the loop loop */ }
    }
    m_last_activity_time = time(NULL);
    m_in_command = false;
    m_locked = false;
  }
}

boost::optional<tools::password_container> wallet3::get_and_verify_password() const
{
//   auto pwd_container = default_password_prompter(m_wallet_file.empty());
//   if (!pwd_container)
//     return boost::none;

//   if (!m_wallet->verify_password(pwd_container->password()))
//   {
//     fail_msg_writer() << tr("invalid password");
//     return boost::none;
//   }
//   return pwd_container;
    return boost::none;
}

// Initialize wallet 
bool wallet3::init()
{
  create_or_open_wallet();
  return true;
}

bool wallet3::run()
{
//   // check and display warning, but go on anyway
//   try_connect_to_daemon();

//   refresh_main(0, ResetNone, true);

//   m_auto_refresh_enabled = !m_wallet->is_offline() && m_wallet->auto_refresh();
//   m_idle_thread = boost::thread([&]{wallet_idle_thread();});

  message_writer(console_color_green, false) << "Background refresh thread started";
  return m_cmd_binder.run_handling([this](){return get_prompt();}, "");
}

std::string wallet3::get_prompt() const
{
//   if (m_locked)
//     return std::string("[") + tr("locked due to inactivity") + "]";
//   std::string addr_start = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0}).substr(0, 6);
//   std::string prompt = std::string("[") + tr("wallet") + " " + addr_start;
//   if (!m_wallet->check_connection(NULL))
//     prompt += tr(" (no daemon)");
//   else if (!m_wallet->is_synced())
//     prompt += tr(" (out of sync)");
//   prompt += "]: ";
  std::string prompt = std::string("[") + tr("wallet") + " "; // + addr_start;
  return prompt;
}

bool wallet3::get_command()
{
    std::string cmd_entered;
    cmd_entered = input_line(
        "Enter command",
        false);
    if (std::cin.eof()) 
    {
      LOG_ERROR("Unexpected std::cin.eof() - Exited seraphis_create_basic::");
      return false;
    }
    return true;
}

bool wallet3::create_or_open_wallet() {
  LOG_PRINT_L3("Basic wallet creation");

  std::string wallet_path;
  std::string confirm_creation;
  std::string confirm_password;

  bool keys_file_exists = false;
  bool wallet_file_exists = false;
  bool wallet_name_valid = false;

  do {
    LOG_PRINT_L3("User asked to specify wallet file name.");
    wallet_path = input_line(
        "Specify a new wallet file name for your Jamtis/Seraphis wallet (e.g., "
        "MyWallet).\nWallet file name (or Ctrl-C to quit)",
        false);
    if (std::cin.eof()) 
    {
      LOG_ERROR("Unexpected std::cin.eof() - Exited seraphis_create_basic::");
      return false;
    }
    wallet_exists(wallet_path, keys_file_exists,
                              wallet_file_exists);
    if (keys_file_exists)
    {
        // Wallet found -> need to be loaded
        tools::success_msg_writer() << tr("Wallet found");
        auto pw = password_prompter(tr("Enter your wallet password"), false);
      try 
      {
        prepare_file_names(wallet_path);
        load_keys_w3(m_keys_file, pw->password());
        if (m_is_wallet3 == false) {
          // if it is not wallet3 then load wallet2
          cout << "Loading wallet2" << endl;

        //   tools::wallet2 *w2 = new tools::wallet2;
        //   w2->load(wallet_path,pw->password());
        //   cout << "Address wallet2 loaded: " << w2->get_address_as_str() << endl;
        } else {
          // wallet3 loaded
          std::cout << get_public_address_w3() << std::endl;
        }
      } catch (...) {
      }

      wallet_name_valid = true;
    } else {
      bool ok = true;
      message_writer() << tr("No wallet found with that name. Confirm "
                                "creation of new wallet named: ")
                          << wallet_path;
      confirm_creation = input_line("", true);
      if (std::cin.eof()) {
        LOG_ERROR("Unexpected std::cin.eof() - Exited "
                  "wallet3::ask_wallet_create_if_needed()");
        return false;
      }
      ok = command_line::is_yes(confirm_creation);
      if (ok) {
        tools::success_msg_writer() << tr("Generating new wallet...");
        auto pw = password_prompter(
            tr("Enter a new password for the wallet"), false);

        create_new_keys_w3(wallet_path, pw->password());

        wallet_name_valid = true;
      }
    }
  } while (!wallet_name_valid);

  LOG_ERROR("Failed out of do-while loop in ask_wallet_create_if_needed()");
  return true;
}

void wallet3::create_new_keys_w3(std::string &wallet_path,
                                    const epee::wipeable_string &password) {
  m_is_wallet3 = true;
  generate_keys();
  prepare_file_names(wallet_path);
  store_keys(m_keys_file, password, false);
}

////////////////////////////

std::string wallet3::input_line(const std::string &prompt, bool yesno) {
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

tools::scoped_message_writer wallet3::message_writer(epee::console_colors color,
                                                     bool bright) {
  return tools::scoped_message_writer(color, bright);
}

boost::optional<tools::password_container>
wallet3::password_prompter(const char *prompt, bool verify) {
  PAUSE_READLINE();
  auto pwd_container = tools::password_container::prompt(verify, prompt);
  if (!pwd_container) {
    tools::fail_msg_writer() << tr("failed to read wallet password");
  }
  return pwd_container;
}

boost::optional<tools::password_container>
wallet3::default_password_prompter(bool verify) {
  return password_prompter(verify ? tr("Enter a new password for the wallet")
                                  : tr("Wallet password"),
                           verify);
}

bool wallet3::wallet_valid_path_format(const std::string &file_path) {
  return !file_path.empty();
}

// generate keys
void wallet3::generate_keys() 
{
    m_account.set_null();
    // m_account.generate(); 
}

// save wallet file...
boost::optional<wallet3::keys_file_data> wallet3::get_keys_file_data(const epee::wipeable_string &password,
                            size_t wallet_type) {
  epee::byte_slice account_data;
  // cryptonote::account_base account = m_account;
  key_container_base account = m_account;

  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);


  bool r = epee::serialization::store_t_to_binary(account, account_data);
  CHECK_AND_ASSERT_MES(r, boost::none, "failed to serialize wallet keys");
  boost::optional<keys_file_data> keys_file_data_struct = keys_file_data{};

  // Create a JSON object with "key_data" and "seed_language" as keys.
  rapidjson::Document json;
  json.SetObject();
  
  rapidjson::Value value_wallet_type(rapidjson::kNumberType);
  value_wallet_type.SetInt(m_is_wallet3 ? 1 : 0);
  json.AddMember("is_wallet3", value_wallet_type, json.GetAllocator());

  value_wallet_type.SetInt(wallet_type);
  json.AddMember("wallet_type", value_wallet_type, json.GetAllocator());


  rapidjson::Value value(rapidjson::kStringType);
  value.SetString(reinterpret_cast<const char *>(account_data.data()),
                  account_data.size());
  json.AddMember("key_data", value, json.GetAllocator());


  rapidjson::Value value2(rapidjson::kNumberType);

  // Serialize the JSON object
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  json.Accept(writer);

  // Encrypt the entire JSON object.
  std::string cipher;
  cipher.resize(buffer.GetSize());
  keys_file_data_struct.get().iv = crypto::rand<crypto::chacha_iv>();
  crypto::chacha20(buffer.GetString(), buffer.GetSize(), key,
                   keys_file_data_struct.get().iv, &cipher[0]);
  keys_file_data_struct.get().account_data = cipher;
  return keys_file_data_struct;
}

bool wallet3::save_to_file(const std::string &path_to_file,
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

bool wallet3::store_keys(const std::string &keys_file_name,
                         const epee::wipeable_string &password,
                         bool watch_only)
{
  boost::optional<keys_file_data> keys_file_data =
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

bool wallet3::prepare_file_names(const std::string &file_path)
{
  do_prepare_file_names(file_path, m_keys_file, m_wallet_file);
  return true;
}

void wallet3::do_prepare_file_names(const std::string &file_path,
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

void wallet3::wallet_exists(const std::string &file_path,
                            bool &keys_file_exists, bool &wallet_file_exists) {
  std::string keys_file, wallet_file;
  do_prepare_file_names(file_path, keys_file, wallet_file);

  boost::system::error_code ignore;
  keys_file_exists = boost::filesystem::exists(keys_file, ignore);
  wallet_file_exists = boost::filesystem::exists(wallet_file, ignore);
}

// load keys...
bool wallet3::load_keys_buf_w3(
    const std::string &keys_buf, const epee::wipeable_string &password,
    boost::optional<crypto::chacha_key> &keys_to_encrypt) 
    {

  // Decrypt the contents
  rapidjson::Document json;
  keys_file_data keys_file_data;
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
      LOG_ERROR("Field key_data not found in JSON");
      return false;
    }
    if (!json["key_data"].IsString()) {
      LOG_ERROR("Field key_data found in JSON, but not String");
      return false;
    }

    account_data = std::string(json["key_data"].GetString(),
                               json["key_data"].GetString() +
                                   json["key_data"].GetStringLength());
  }

  r = epee::serialization::load_t_from_binary(m_account, account_data);
//   THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);

  GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, is_wallet3, int, Int, false, false);
  m_is_wallet3 = field_is_wallet3;

  GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, wallet_type, int, Int, false, false);
  m_account.set_wallet_type(field_wallet_type);

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

bool wallet3::load_from_file(const std::string &path_to_file,
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
bool wallet3::load_keys_w3(const std::string &keys_file_name,
                           const epee::wipeable_string &password) {
  std::string keys_file_buf;
  bool r = load_from_file(keys_file_name, keys_file_buf);

  // Load keys from buffer
  boost::optional<crypto::chacha_key> keys_to_encrypt;
  r = load_keys_buf_w3(keys_file_buf, password, keys_to_encrypt);

  return r;
}
//----------------------------------------------------------------------------------------------------

void wallet3::setup_keys(const epee::wipeable_string &password) {
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);

  // re-encrypt, but keep viewkey unencrypted
  m_account.encrypt_keys(key);
//   m_account.decrypt_viewkey(key);

//   m_account_w2.encrypt_keys(key);
//   m_account_w2.decrypt_viewkey(key);
}

void wallet3::encrypt_keys(const crypto::chacha_key &key) {
  m_account.encrypt_keys(key);
//   m_account.decrypt_viewkey(key);
}

void wallet3::decrypt_keys(const crypto::chacha_key &key) {
//   m_account.encrypt_viewkey(key);
  m_account.decrypt_keys(key);
}

void wallet3::encrypt_keys(const epee::wipeable_string &password) {
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);
  encrypt_keys(key);
}

void wallet3::decrypt_keys(const epee::wipeable_string &password) {
  crypto::chacha_key key;
  crypto::generate_chacha_key(password.data(), password.size(), key,
                              m_kdf_rounds);
  decrypt_keys(key);
}

std::string wallet3::get_public_address_w3() {
  return m_account.get_public_address_str();
}

}