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

// Initialize wallet 
bool wallet3::init()
{
  m_gen_load_store.create_or_open_wallet(m_key_container);
  return true;
}

bool wallet3::run()
{
//   // check and display warning, but go on anyway
//   try_connect_to_daemon();

//   refresh_main(0, ResetNone, true);

//   m_auto_refresh_enabled = !m_wallet->is_offline() && m_wallet->auto_refresh();
    m_gen_load_store.m_idle_thread = boost::thread([&]{m_gen_load_store.wallet_idle_thread();});
    m_gen_load_store.message_writer(console_color_green, false) << "Background refresh thread started";
    return m_gen_load_store.m_cmd_binder.run_handling([this](){return m_gen_load_store.get_prompt();}, "");
}


void wallet3::stop()
{
  m_gen_load_store.m_cmd_binder.stop_handling();
  m_gen_load_store.close_wallet();
}

}