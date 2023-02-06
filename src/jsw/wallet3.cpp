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

// paired header
#include "wallet3.h"

// local headers
#include "byte_slice.h"
#include "common/boost_serialization_helper.h"
#include "common/command_line.h"
#include "common/i18n.h"
#include "common/json_util.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "console_handler.h"
#include "crypto/chacha.h"
#include "key_container.h"
#include "misc_log_ex.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_mocks/jamtis_mock_keys.h"
#include "serialization/binary_utils.h"
#include "serialization/json_object.h"
#include "serialization/string.h"
#include "storages/portable_storage_template_helper.h"
#include "string_tools.h"

// seraphis lib
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_main/enote_scanning.h"
#include "seraphis_main/enote_scanning_context_simple.h"
#include "seraphis_mocks/seraphis_mocks.h"

extern "C"
{
#include "crypto/crypto-ops.h"
#include "crypto/keccak.h"
}

// standard headers
#include <openssl/pem.h>

#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/format.hpp>
#include <boost/format/format_fwd.hpp>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

// use boost bind placeholders for now
#define BOOST_BIND_GLOBAL_PLACEHOLDERS 1
#include <boost/bind.hpp>

using namespace jsw;
using namespace epee;
using namespace std;
using namespace sp;
using namespace sp::jamtis;
using namespace jamtis::mocks;
using namespace sp::mocks;

static const std::string ASCII_OUTPUT_MAGIC = "MoneroAsciiDataV1";

#define REFRESH_PERIOD 90                   // seconds
#define DEFAULT_INACTIVITY_LOCK_TIMEOUT 90  // seconds

#define PRINT_USAGE(usage_help) fail_msg_writer() << boost::format(tr("usage: %s")) % usage_help;

const char *USAGE_SHOW_BALANCE("balance [detail]");
const char *USAGE_SHOW_TRANSFER("transfer <address> <amount>");
const char *USAGE_SHOW_VIEWBALANCE("save_viewbalance");

int main(int argc, char *argv[])
{
    wallet3 my_wallet;
    my_wallet.init();
    my_wallet.run();
    std::cout << "Bye" << std::endl;
    my_wallet.stop();
    return 1;
}

namespace jsw
{

bool wallet3::init()
{
    create_or_open_wallet(m_key_container);
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::run()
{
    m_idle_thread = boost::thread([&] { wallet_idle_thread(); });
    message_writer(console_color_green, false) << "Background refresh thread started";
    return m_cmd_binder.run_handling([this]() { return get_prompt(); }, "");
}
//----------------------------------------------------------------------------------------------------
void wallet3::stop()
{
    m_cmd_binder.stop_handling();
    close_wallet();
}
//----------------------------------------------------------------------------------------------------
wallet3::wallet3()
    : m_last_activity_time(time(NULL)),
      m_idle_run(true),
      m_locked(false),
      m_in_command(false),
      m_inactivity_lock_timeout(DEFAULT_INACTIVITY_LOCK_TIMEOUT)
{
    m_cmd_binder.set_handler("help", boost::bind(&wallet3::on_command, this, &wallet3::help, _1),
                             tr(USAGE_SHOW_VIEWBALANCE), tr("Show help."));
    m_cmd_binder.set_handler("save_viewbalance",
                             boost::bind(&wallet3::on_command, this, &wallet3::save_viewbalance, _1),
                             tr(USAGE_SHOW_VIEWBALANCE), tr("Create a viewbalance wallet from a master wallet."));
    m_cmd_binder.set_handler("transfer", boost::bind(&wallet3::on_command, this, &wallet3::transfer, _1),
                             tr(USAGE_SHOW_TRANSFER), tr("Transfer <address> <amount>."));
    m_cmd_binder.set_handler("balance", boost::bind(&wallet3::on_command, this, &wallet3::show_balance, _1),
                             tr(USAGE_SHOW_BALANCE),
                             tr("Show the wallet's balance of the currently selected account."));
    m_cmd_binder.set_handler("create_money", boost::bind(&wallet3::on_command, this, &wallet3::create_money, _1),
                             tr("Create fake enotes for wallets."));
    m_cmd_binder.set_unknown_command_handler(boost::bind(&wallet3::on_command, this, &wallet3::on_unknown_command, _1));
    m_cmd_binder.set_empty_command_handler(boost::bind(&wallet3::on_empty_command, this));
    m_cmd_binder.set_cancel_handler(boost::bind(&wallet3::on_cancelled_command, this));
}
//----------------------------------------------------------------------------------------------------
bool wallet3::on_unknown_command(const std::vector<std::string> &args)
{
    if (args[0] == "exit" || args[0] == "q")  // backward compat
        return false;
    tools::fail_msg_writer() << boost::format(tr("Unknown command '%s', try 'help'")) % args.front();
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::on_empty_command() { return true; }
//----------------------------------------------------------------------------------------------------
bool wallet3::on_cancelled_command()
{
    check_for_inactivity_lock(false);
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::on_command(bool (wallet3::*cmd)(const std::vector<std::string> &), const std::vector<std::string> &args)
{
    m_last_activity_time = time(NULL);

    m_in_command = true;
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler(
        [&]()
        {
            m_last_activity_time = time(NULL);
            m_in_command = false;
        });

    check_for_inactivity_lock(false);
    return (this->*cmd)(args);
}
//----------------------------------------------------------------------------------------------------
std::string wallet3::get_prompt() const
{
    if (m_locked) return std::string("[") + tr("locked due to inactivity") + "]";
    std::string prompt = std::string("[") + tr("wallet ") + m_key_container.get_public_address_str().substr(0, 16);
    prompt += "]: ";
    return prompt;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::get_command()
{
    std::string cmd_entered;
    cmd_entered = input_line("Enter command", false);
    if (std::cin.eof())
    {
        LOG_ERROR("Unexpected std::cin.eof() - Exited seraphis_create_basic::");
        return false;
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
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
            tools::msg_writer() << " " << std::endl
                                << "        .n.      Your wallet was locked        " << std::endl
                                << "       /___\\      while you were away.  " << std::endl
                                << "       [|||]  See \"help set\" to configure it.   " << std::endl
                                << "       |-  | " << std::endl
                                << "       |.- |                p " << std::endl
                                << "~^=~^~-|_.-|~^-~^~ ~^~ -^~^~|\\ ~^-~^~- " << std::endl
                                << "^   .=.| _.|__  ^       ~  /| \\  " << std::endl
                                << " ~ /:. \\  _|_/\\    ~      /_| _\\  ^ " << std::endl
                                << ".-/::.  |   |::|-._    ^  \\____/ " << std::endl
                                << "  `===-'-----'"
                                   "`  '-.              ~"
                                << std::endl
                                << "" << std::endl;
        }
        while (1)
        {
            const char *inactivity_msg = user ? "" : tr("Locked due to inactivity.");
            tools::msg_writer() << inactivity_msg << (inactivity_msg[0] ? " " : "")
                                << tr("The wallet password is required to unlock the console.");

            try
            {
                if (get_and_verify_password()) break;
            }
            catch (...)
            { /* do nothing, just let the loop loop */
            }
        }
        m_last_activity_time = time(NULL);
        m_in_command = false;
        m_locked = false;
    }
}
//----------------------------------------------------------------------------------------------------
void wallet3::wallet_idle_thread()
{
    const boost::posix_time::ptime start_time = boost::posix_time::microsec_clock::universal_time();
    while (true)
    {
        boost::unique_lock<boost::mutex> lock(m_idle_mutex);
        if (!m_idle_run.load(std::memory_order_relaxed)) break;

        // if another thread was busy (ie, a foreground refresh thread), we'll
        // end up here at some random time that's not what we slept for, so we
        // should not call refresh now or we'll be leaking that fact through
        // timing
        const boost::posix_time::ptime now0 = boost::posix_time::microsec_clock::universal_time();
        const uint64_t dt_actual = (now0 - start_time).total_microseconds() % 1000000;
#ifdef _WIN32
        static const uint64_t threshold = 10000;
#else
        static const uint64_t threshold = 2000;
#endif
        if (dt_actual < threshold)  // if less than a threshold... would a very
                                    // slow machine always miss it ?
        {
#ifndef _WIN32
            m_inactivity_checker.do_call(boost::bind(&wallet3::check_inactivity, this));
#endif
            if (!m_idle_run.load(std::memory_order_relaxed)) break;
        }

        // aim for the next multiple of 1 second
        const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
        const auto dt = (now - start_time).total_microseconds();
        const auto wait = 1000000 - dt % 1000000;
        m_idle_cond.wait_for(lock, boost::chrono::microseconds(wait));
    }
}
//----------------------------------------------------------------------------------------------------
bool wallet3::check_inactivity()
{
    // inactivity lock
    if (!m_locked && !m_in_command)
    {
        const uint32_t seconds = inactivity_lock_timeout();
        if (seconds > 0 && time(NULL) - m_last_activity_time > seconds)
        {
            m_locked = true;
            m_cmd_binder.cancel_input();
        }
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::close_wallet()
{
    if (m_idle_run.load(std::memory_order_relaxed))
    {
        m_idle_run.store(false, std::memory_order_relaxed);
        // m_suspend_rpc_payment_mining.store(true, std::memory_order_relaxed);
        {
            boost::unique_lock<boost::mutex> lock(m_idle_mutex);
            m_idle_cond.notify_one();
        }
        m_idle_thread.join();
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
boost::optional<tools::password_container> wallet3::get_and_verify_password()
{
    auto pwd_container = default_password_prompter(false);
    if (!pwd_container) return boost::none;

    if (!verify_password(pwd_container->password()))
    {
        tools::fail_msg_writer() << tr("invalid password");
        return boost::none;
    }
    return pwd_container;
    return boost::none;
}
//----------------------------------------------------------------------------------------------------
std::string wallet3::input_line(const std::string &prompt, bool yesno)
{
    PAUSE_READLINE();
    std::cout << prompt;
    if (yesno) std::cout << "  (Y/Yes/N/No)";
    std::cout << ": " << std::flush;

    std::string buf;
#ifdef _WIN32
    buf = tools::input_line_win();
#else
    std::getline(std::cin, buf);
#endif

    return epee::string_tools::trim(buf);
}
//----------------------------------------------------------------------------------------------------
tools::scoped_message_writer wallet3::message_writer(epee::console_colors color, bool bright)
{
    return tools::scoped_message_writer(color, bright);
}
//----------------------------------------------------------------------------------------------------
boost::optional<tools::password_container> wallet3::password_prompter(const char *prompt, bool verify)
{
    PAUSE_READLINE();
    auto pwd_container = tools::password_container::prompt(verify, prompt);
    if (!pwd_container)
    {
        tools::fail_msg_writer() << tr("failed to read wallet password");
    }
    return pwd_container;
}
//----------------------------------------------------------------------------------------------------
boost::optional<tools::password_container> wallet3::default_password_prompter(bool creation)
{
    return password_prompter(creation ? tr("Enter a new password for the wallet") : tr("Wallet password"), creation);
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_or_open_wallet(key_container_base &key_container)
{
    LOG_PRINT_L3("Basic wallet creation");

    std::string wallet_path;
    std::string confirm_creation;
    std::string confirm_password;

    bool keys_file_exists = false;
    bool wallet_file_exists = false;
    bool wallet_name_valid = false;

    do
    {
        LOG_PRINT_L3("User asked to specify wallet file name.");
        wallet_path = input_line(
            "Enter your wallet file name or specify a new wallet file "
            "name for your Jamtis/Seraphis wallet (e.g., "
            "MyWallet).\nWallet file name (or Ctrl-C to quit)",
            false);
        if (std::cin.eof())
        {
            LOG_ERROR("Unexpected std::cin.eof() - Exited seraphis_create_basic::");
            return false;
        }
        wallet_exists(wallet_path, keys_file_exists, wallet_file_exists);
        if (keys_file_exists)
        {
            // Wallet found -> need to be loaded
            tools::success_msg_writer() << tr("Wallet found");
            auto pw = password_prompter(tr("Enter your wallet password"), false);
            try
            {
                prepare_file_names(wallet_path);
                if (load_keys_w3(m_keys_file, pw->password(), key_container))
                {
                    if (m_is_wallet3 == false)
                    {
                        // if it is not wallet3 then load wallet2
                        cout << "Loading wallet2" << endl;
                    }
                    else
                    {
                        // wallet3 loaded print wallet type and 0 address
                        print_wallet_type();
                        std::cout << get_public_address_w3(key_container) << std::endl;
                    }
                    wallet_name_valid = true;
                }
                else
                {
                    tools::fail_msg_writer() << tr("Wrong password.");
                }
            }
            catch (...)
            {
            }
        }
        else
        {
            bool ok = true;
            message_writer() << tr("No wallet found with that name. Confirm "
                                   "creation of new wallet named: ")
                             << wallet_path;
            confirm_creation = input_line("", true);
            if (std::cin.eof())
            {
                LOG_ERROR(
                    "Unexpected std::cin.eof() - Exited "
                    "wallet3::ask_wallet_create_if_needed()");
                return false;
            }
            ok = command_line::is_yes(confirm_creation);
            if (ok)
            {
                tools::success_msg_writer() << tr("Generating new wallet...");
                auto pw = password_prompter(tr("Enter a new password for the wallet"), false);

                create_new_keys_w3(wallet_path, pw->password(), key_container);
                std::cout << get_public_address_w3(key_container) << std::endl;

                wallet_name_valid = true;
            }
        }
    }
    while (!wallet_name_valid);

    LOG_ERROR("Failed out of do-while loop in ask_wallet_create_if_needed()");
    return true;
}
//----------------------------------------------------------------------------------------------------
void wallet3::create_new_keys_w3(std::string &wallet_path, const epee::wipeable_string &password,
                                 key_container_base &key_container)
{
    m_is_wallet3 = true;
    key_container.generate_master();
    prepare_file_names(wallet_path);
    store_keys(m_keys_file, password, key_container);
}
//----------------------------------------------------------------------------------------------------
void wallet3::create_viewbalance(const epee::wipeable_string &password, key_container_base &key_container)
{
    m_is_wallet3 = true;
    key_container_base keys_new;
    key_container.get_viewbalance(keys_new);
    store_keys(m_wallet_file + "_viewbalance.keys", password, keys_new);
}
//----------------------------------------------------------------------------------------------------
void wallet3::print_wallet_type()
{
    switch (m_wallet_type)
    {
        case 0:
            tools::msg_writer() << tr("Master wallet loaded.");
            break;
        case 1:
            tools::msg_writer() << tr("View-balance wallet loaded.");
            break;
        default:
            tools::fail_msg_writer() << tr("Failed loading wallet type.");
    }
}
//----------------------------------------------------------------------------------------------------
boost::optional<wallet3::keys_file_data> wallet3::get_keys_file_data(const epee::wipeable_string &password,
                                                                     key_container_base &key_container)
{
    epee::byte_slice key_container_data;

    crypto::chacha_key key;
    crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);

    bool r = epee::serialization::store_t_to_binary(key_container, key_container_data);
    CHECK_AND_ASSERT_MES(r, boost::none, "failed to serialize wallet keys");
    boost::optional<keys_file_data> keys_file_data_struct = keys_file_data{};

    // Create a JSON object with "key_data" and "seed_language" as keys.
    rapidjson::Document json;
    json.SetObject();

    rapidjson::Value value_wallet_type(rapidjson::kNumberType);
    value_wallet_type.SetInt(m_is_wallet3 ? 1 : 0);
    json.AddMember("is_wallet3", value_wallet_type, json.GetAllocator());

    // value_wallet_type.SetInt(wallet_type);
    // json.AddMember("wallet_type", value_wallet_type, json.GetAllocator());

    rapidjson::Value value(rapidjson::kStringType);
    value.SetString(reinterpret_cast<const char *>(key_container_data.data()), key_container_data.size());
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
    crypto::chacha20(buffer.GetString(), buffer.GetSize(), key, keys_file_data_struct.get().iv, &cipher[0]);
    keys_file_data_struct.get().account_data = cipher;
    return keys_file_data_struct;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::save_to_file(const std::string &path_to_file, const std::string &raw, bool is_printable)
{
    FILE *fp = fopen(path_to_file.c_str(), "w+");
    if (!fp)
    {
        MERROR("Failed to open wallet file for writing: " << path_to_file << ": " << strerror(errno));
        return false;
    }

    // Save the result b/c we need to close the fp before returning
    // success/failure.
    int write_result = PEM_write(fp, ASCII_OUTPUT_MAGIC.c_str(), "", (const unsigned char *)raw.c_str(), raw.length());
    fclose(fp);

    if (write_result == 0)
    {
        return false;
    }
    else
    {
        return true;
    }
}
//----------------------------------------------------------------------------------------------------
bool wallet3::store_keys(const std::string &keys_file_name, const epee::wipeable_string &password,
                         key_container_base &key_container)
{
    boost::optional<keys_file_data> keys_file_data = get_keys_file_data(password, key_container);
    CHECK_AND_ASSERT_MES(keys_file_data != boost::none, false, "failed to generate wallet keys data");

    std::string tmp_file_name = keys_file_name + ".new";
    std::string buf;
    bool r = ::serialization::dump_binary(keys_file_data.get(), buf);
    r = r && save_to_file(tmp_file_name, buf, true);
    CHECK_AND_ASSERT_MES(r, false, "failed to generate wallet keys file " << tmp_file_name);

    std::error_code e = tools::replace_file(tmp_file_name, keys_file_name);

    if (e)
    {
        boost::filesystem::remove(tmp_file_name);
        LOG_ERROR("failed to update wallet keys file " << keys_file_name);
        return false;
    }

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::prepare_file_names(const std::string &file_path)
{
    do_prepare_file_names(file_path, m_keys_file, m_wallet_file);
    return true;
}
//----------------------------------------------------------------------------------------------------
void wallet3::do_prepare_file_names(const std::string &file_path, std::string &keys_file, std::string &wallet_file)
{
    keys_file = file_path;
    wallet_file = file_path;
    if (string_tools::get_extension(keys_file) == "keys")
    {  // provided keys file name
        wallet_file = string_tools::cut_off_extension(wallet_file);
    }
    else
    {  // provided wallet file name
        keys_file += ".keys";
    }
}
//----------------------------------------------------------------------------------------------------
void wallet3::wallet_exists(const std::string &file_path, bool &keys_file_exists, bool &wallet_file_exists)
{
    std::string keys_file, wallet_file;
    do_prepare_file_names(file_path, keys_file, wallet_file);

    boost::system::error_code ignore;
    keys_file_exists = boost::filesystem::exists(keys_file, ignore);
    wallet_file_exists = boost::filesystem::exists(wallet_file, ignore);
}
//----------------------------------------------------------------------------------------------------
bool wallet3::load_keys_buf_w3(const std::string &keys_buf, const epee::wipeable_string &password,
                               boost::optional<crypto::chacha_key> &keys_to_encrypt,
                               key_container_base &key_container_out)
{
    // Decrypt the contents
    rapidjson::Document json;
    keys_file_data keys_file_data;
    bool encrypted_secret_keys = false;
    bool r = ::serialization::parse_binary(keys_buf, keys_file_data);
    CHECK_AND_ASSERT_MES(r, false, "Load keys buf: Failed to parse binary");

    crypto::chacha_key key;
    crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
    std::string account_data;
    account_data.resize(keys_file_data.account_data.size());
    crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv,
                     &account_data[0]);
    if (json.Parse(account_data.c_str()).HasParseError() || !json.IsObject())
    {
        // printf("inside this if");
        crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv,
                        &account_data[0]);
    }
    // The contents should be JSON if the wallet follows the new format.
    if (json.IsObject())
    {
        if (!json.HasMember("key_data"))
        {
            LOG_ERROR("Field key_data not found in JSON");
            return false;
        }
        if (!json["key_data"].IsString())
        {
            LOG_ERROR("Field key_data found in JSON, but not String");
            return false;
        }

        account_data = std::string(json["key_data"].GetString(),
                                   json["key_data"].GetString() + json["key_data"].GetStringLength());
    }

    r = epee::serialization::load_t_from_binary(key_container_out, account_data);
    CHECK_AND_ASSERT_MES(r, false, "Load keys buf: Failed to load t from binary");
    //   THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, is_wallet3, int, Int, false, false);
    m_is_wallet3 = field_is_wallet3;

    // GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, wallet_type, int, Int, false, false);
    // key_container_out.set_wallet_type(field_wallet_type);

    if (r)
    {
        if (encrypted_secret_keys)
        {
            key_container_out.decrypt_keys(key);
        }
        else
        {
            keys_to_encrypt = key;
        }
    }

    set_wallet_type(key_container_out.get_wallet_type());

    return true;
}
//----------------------------------------------------------------------------------------------------
void wallet3::set_wallet_type(size_t type) { m_wallet_type = type; }
//----------------------------------------------------------------------------------------------------
bool wallet3::load_from_file(const std::string &path_to_file, std::string &target_str, size_t max_size)
{
    std::string data;
    bool r = epee::file_io_utils::load_file_to_string(path_to_file, data, max_size);
    if (!r)
    {
        return false;
    }

    if (!boost::algorithm::contains(boost::make_iterator_range(data.begin(), data.end()), ASCII_OUTPUT_MAGIC))
    {
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

    try
    {
        target_str = std::string((const char *)openssl_data, len);
    }
    catch (...)
    {
        success = 0;
    }

    OPENSSL_free((void *)name);
    OPENSSL_free((void *)header);
    OPENSSL_free((void *)openssl_data);
    BIO_free(b);

    if (success == 0)
    {
        return false;
    }
    else
    {
        return true;
    }
}
//----------------------------------------------------------------------------------------------------
bool wallet3::load_keys_w3(const std::string &keys_file_name, const epee::wipeable_string &password,
                           key_container_base &key_container)
{
    std::string keys_file_buf;
    bool r = load_from_file(keys_file_name, keys_file_buf);

    // Load keys from buffer
    boost::optional<crypto::chacha_key> keys_to_encrypt;
    r = load_keys_buf_w3(keys_file_buf, password, keys_to_encrypt, key_container);

    return r;
}
//----------------------------------------------------------------------------------------------------
void wallet3::setup_keys(const epee::wipeable_string &password, key_container_base &key_container)
{
    crypto::chacha_key key;
    crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);

    // re-encrypt, but keep viewkey unencrypted
    key_container.encrypt_keys(key);
    //   m_account.decrypt_viewkey(key);

    //   m_account_w2.encrypt_keys(key);
    //   m_account_w2.decrypt_viewkey(key);
}
//----------------------------------------------------------------------------------------------------
void wallet3::encrypt_keys(const crypto::chacha_key &key, key_container_base &key_container)
{
    key_container.encrypt_keys(key);
    //   m_account.decrypt_viewkey(key);
}
//----------------------------------------------------------------------------------------------------
void wallet3::decrypt_keys(const crypto::chacha_key &key, key_container_base &key_container)
{
    //   m_account.encrypt_viewkey(key);
    key_container.decrypt_keys(key);
}
//----------------------------------------------------------------------------------------------------
void wallet3::encrypt_keys(const epee::wipeable_string &password, key_container_base &key_container)
{
    crypto::chacha_key key;
    crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
    encrypt_keys(key, key_container);
}
//----------------------------------------------------------------------------------------------------
void wallet3::decrypt_keys(const epee::wipeable_string &password, key_container_base &key_container)
{
    crypto::chacha_key key;
    crypto::generate_chacha_key(password.data(), password.size(), key, m_kdf_rounds);
    decrypt_keys(key, key_container);
}
//----------------------------------------------------------------------------------------------------
bool wallet_valid_path_format(const std::string &file_path) { return !file_path.empty(); }
//----------------------------------------------------------------------------------------------------
std::string wallet3::get_public_address_w3(key_container_base &key_container)
{
    return key_container.get_public_address_str();
}
//----------------------------------------------------------------------------------------------------
bool wallet3::verify_password(const epee::wipeable_string &password)
{
    // this temporary unlocking is necessary for Windows (otherwise the file
    // couldn't be loaded).
    unlock_keys_file();
    bool r = verify_password(m_keys_file, password, m_kdf_rounds);
    lock_keys_file();
    return r;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::verify_password(const std::string &keys_file_name, const epee::wipeable_string &password,
                              uint64_t kdf_rounds)
{
    rapidjson::Document json;
    keys_file_data keys_file_data;
    std::string buf;
    bool encrypted_secret_keys = false;
    bool r = load_from_file(keys_file_name, buf);

    // Decrypt the contents
    r = ::serialization::parse_binary(buf, keys_file_data);
    // THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal
    // error: failed to deserialize \"" + keys_file_name + '\"');
    crypto::chacha_key key;
    crypto::generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
    std::string key_container_str;
    key_container_str.resize(keys_file_data.account_data.size());
    crypto::chacha20(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv,
                     &key_container_str[0]);
    if (json.Parse(key_container_str.c_str()).HasParseError() || !json.IsObject())
        crypto::chacha8(keys_file_data.account_data.data(), keys_file_data.account_data.size(), key, keys_file_data.iv,
                        &key_container_str[0]);

    // The contents should be JSON if the wallet follows the new format.
    if (json.Parse(key_container_str.c_str()).HasParseError())
    {
        // old format before JSON wallet key file format
    }
    else
    {
        key_container_str = std::string(json["key_data"].GetString(),
                                        json["key_data"].GetString() + json["key_data"].GetStringLength());
        // GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, encrypted_secret_keys,
        // uint32_t, Uint, false, false); encrypted_secret_keys =
        // field_encrypted_secret_keys;
    }

    key_container_base key_container;
    r = epee::serialization::load_t_from_binary(key_container, key_container_str);
    // Use wallet exceptions instead...
    CHECK_AND_ASSERT_THROW_MES(r, "Verify password: Failed to load t from binary");
    //   THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);

    GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, is_wallet3, int, Int, false, false);
    m_is_wallet3 = field_is_wallet3;

    // GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, wallet_type, int, Int, false, false);
    // key_container.set_wallet_type(field_wallet_type);

    if (r)
    {
        if (encrypted_secret_keys)
        {
            key_container.decrypt_keys(key);
        }
        // const mocks::jamtis_mock_keys& keys = key_container.get_keys();
    }
    else
    {
        return false;
    }

    // Verify function here. Wallet filename should be private.
    r &= key_container.verify_keys();
    return r;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::lock_keys_file()
{
    if (m_wallet_file.empty()) return true;
    if (m_keys_file_locker)
    {
        MDEBUG(m_keys_file << " is already locked.");
        return false;
    }
    m_keys_file_locker.reset(new tools::file_locker(m_keys_file));
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::unlock_keys_file()
{
    if (m_wallet_file.empty()) return true;
    if (!m_keys_file_locker)
    {
        MDEBUG(m_keys_file << " is already unlocked.");
        return false;
    }
    m_keys_file_locker.reset();
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::is_keys_file_locked() const
{
    if (m_wallet_file.empty()) return false;
    return m_keys_file_locker->locked();
}
//----------------------------------------------------------------------------------------------------
bool wallet3::save_viewbalance(const std::vector<std::string> &args)
{
    auto pw = password_prompter(tr("Enter your wallet password"), false);
    if (load_keys_w3(m_keys_file, pw->password(), m_key_container))
    {
        // create_new_keys_w3(wallet_path, pw->password(), key_container);
        create_viewbalance(pw->password(), m_key_container);
        tools::success_msg_writer() << tr("Viewbalance wallet created.");
    }
    else
    {
        tools::fail_msg_writer() << tr("Failed. Wrong password.");
    }

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_money(const std::vector<std::string> &args)
{
    std::vector<std::string> local_args = args;

    JamtisDestinationV1 destination_address;
    if (local_args.size() == 0)
    {
        // JamtisDestinationV1 destination_address_random;
        make_random_address_for_user(m_key_container.get_keys_sp(), destination_address);
    }
    else
    {
        m_key_container.get_destination_from_str(local_args[0], destination_address);
        // std::cout << "Destination K1: " << destination_address.m_addr_K1 <<
        // std::endl; std::cout << "K_1: "<< destination_address.m_addr_K1 <<
        // std::endl; std::cout << "K_2: " <<
        // epee::string_tools::pod_to_hex(destination_address.m_addr_K2) <<
        // std::endl; std::cout << "K_3: " <<
        // epee::string_tools::pod_to_hex(destination_address.m_addr_K3) <<
        // std::endl; std::cout << "t: " <<
        // epee::string_tools::pod_to_hex(destination_address.m_addr_tag) <<
        // std::endl;
    }

    const RefreshLedgerEnoteStoreConfig refresh_config{
        .m_reorg_avoidance_depth = 1, .m_max_chunk_size = 1, .m_max_partialscan_attempts = 0};

    send_sp_coinbase_amounts_to_user({1000, 1000, 1000, 1000, 1000}, destination_address, m_ledger_context);

    refresh_user_enote_store(m_key_container.get_keys_sp(), refresh_config, m_ledger_context, m_enote_store);

    tools::success_msg_writer() << tr("Five enotes of 1000 each were created to this wallet.");
    // tools::success_msg_writer() << boost::format(tr(" %21s")) %
    // local_args[0];
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::show_balance(const std::vector<std::string> &args)
{
    const RefreshLedgerEnoteStoreConfig refresh_config{
        .m_reorg_avoidance_depth = 1, .m_max_chunk_size = 1, .m_max_partialscan_attempts = 0};
    refresh_user_enote_store(m_key_container.get_keys_sp(), refresh_config, m_ledger_context, m_enote_store);

    auto balance = m_enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN}, {SpEnoteSpentStatus::SPENT_ONCHAIN});
    tools::msg_writer() << tr("Wallet balance: ");
    tools::msg_writer() << boost::format(tr("%15s")) % balance;
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::transfer(const std::vector<std::string> &args)
{
    std::vector<std::string> local_args = args;

    JamtisDestinationV1 destination_address;
    if (local_args.size() != 2)
    {
        tools::fail_msg_writer() << tr("Invalid number of arguments");
        return true;
    }

    m_key_container.get_destination_from_str(local_args[0], destination_address);
    rct::xmr_amount amount{std::stoull(local_args[1])};
    // cryptonote::parse_amount(amount,local_args[1]);

    // Data for transfer
    const RefreshLedgerEnoteStoreConfig refresh_config{
        .m_reorg_avoidance_depth = 1, .m_max_chunk_size = 1, .m_max_partialscan_attempts = 0};

    refresh_user_enote_store(m_key_container.get_keys_sp(), refresh_config, m_ledger_context, m_enote_store);
    auto balance = m_enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN}, {SpEnoteSpentStatus::SPENT_ONCHAIN});
    if (amount >= balance)
    {
        tools::fail_msg_writer() << tr("Fail. You are trying to spend more than your available balance.");
        return true;
    }

    const FeeCalculatorMockTrivial fee_calculator;  // just do a trivial calculator
                                                    // for now (fee = fee/weight
                                                    // * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{.m_bin_radius = 1, .m_num_bin_members = 2};

    const InputSelectorMockV1 input_selector{m_enote_store};
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    //  make sure to have enough fake enotes to the ledger so we can reliably
    //  make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
        static_cast<std::size_t>(compute_bin_width(bin_config.m_bin_radius)), 0);

    SpTxSquashedV1 single_tx;
    construct_tx_for_mock_ledger_v1(m_key_container.get_keys_legacy(), m_key_container.get_keys_sp(), input_selector,
                                    fee_calculator, fee_per_tx_weight, max_inputs,
                                    {{amount, destination_address, TxExtra{}}}, legacy_ring_size, ref_set_decomp_n,
                                    ref_set_decomp_m, bin_config, m_ledger_context, single_tx);

    // validate and submit to the mock ledger
    const TxValidationContextMock tx_validation_context{m_ledger_context};
    CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
                               "transfer funds single mock: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, m_ledger_context),
                               "transfer funds single mock: adding tx to mock ledger failed.");

    refresh_user_enote_store(m_key_container.get_keys_sp(), refresh_config, m_ledger_context, m_enote_store);

    rct::key tx_id;
    get_sp_tx_squashed_v1_txid(single_tx, tx_id);

    tools::msg_writer() << tr("Transaction ") << epee::string_tools::pod_to_hex(tx_id) << tr(" submitted to network.");

    return true;
}

bool wallet3::help(const std::vector<std::string> &args)
{
    if (args.empty())
    {
        message_writer() << "";
        message_writer() << tr("Important commands:");
        message_writer() << "";
        message_writer() << tr("\"help <command>\" - Show a command's documentation.");
        message_writer() << "";
        message_writer() << tr("\"create_money \" - Creates 5 enotes of 1000 each to own wallet.");
        message_writer() << tr("\"transfer <address> <amount>\" - Send XMR to an address.");
        message_writer() << tr("\"balance\" - Show balance.");
        message_writer() << tr("\"save_viewbalance\" - Save view-balance wallet.");
    }
    return true;
}
}  // namespace jsw