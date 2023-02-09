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


#include "common/checksum_jamtis.h"

#include <cstdint>
#include <string>

#include "common/base32.h"
#include "gtest/gtest.h"
#include "string_tools.h"

using namespace tools;
using namespace std;

void do_test_checksum(std::string &without, std::string &checksum)
{
    std::string address_with_checksum{tools::jamtis_checksum::jamtis_add_checksum(without)};
    ASSERT_EQ(address_with_checksum, without + checksum);
}

void do_test_checksum_vector(std::vector<std::string> &without, std::vector<std::string> &checksum)
{
    for (int i = 0; i < without.size(); i++)
    {
        std::string address_with_checksum{tools::jamtis_checksum::jamtis_add_checksum(without[i])};
        ASSERT_EQ(address_with_checksum, without[i] + checksum[i]);
    }
}

TEST(checksum_jamtis, checksum_simple)
{
    std::string t1{
        "xmra1mj0b1977bw3ympyh2yxd7hjymrw8crc9kin0dkm8d3wdu8jdhf3fkdpmgxfkbywbb9mdwkhkya4jtfn0d5h7s49bfyji1936w19tyf390"
        "6ypj09n64runqjrxwp6k2s3phxwm6wrb5c0b6c1ntrg2muge0cwdgnnr7u7bgknya9arksrj0re7wh"};
    std::string checksum_t1{"kckh51ik"};

    do_test_checksum(t1, checksum_t1);
}

TEST(checksum_jamtis, checksum_vector)
{
    std::vector<std::string> address;
    std::vector<std::string> checksum;

    // Addresses generated using the gen_jamtis_destination_v1() and converted into base32
    // Checksum generated using the Python script from tevador
    // https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024#appendix-a-checksum

    address.push_back(
        "0sn89r3k445wr1qsxqt9ymsuixkcxuu7n98dwfxerkdutpcdp51k2ef2x4y9iuec3sg46t43aef5jjg9a356gu9ki7ykidgwnaxpr4yj1m79x1"
        "3s4estqq6ejc7ni9gsni7p2dg6u4t4eh6whmq46aj5e669bp62uhkxysfb9m3b04y9yne3hm2");
    checksum.push_back("4xfwe1x3");
    address.push_back(
        "qndhii75d5nb1x8ej389pb3rbf3ef4sg2719bf6fr94pi804xp5y0fphu5p09de8wqy1604wup9jh5aqq4druagy9c3xtfawej976mgwha947m"
        "aet7myg8qsbikja8fw6kf3a968i8gcr0ptm08k6e1irsrxtj2jdd6ec2ygrg8uxwia4ucg4d0");
    checksum.push_back("pykt4an5");
    address.push_back(
        "w6texg32h5gfburwqh7d34h92rs0b7b36yxexequn1cwges3guqi22jq1bgknhj1yat350dr6rx40tgs2c409m5enbrxr3cxf6750jbtknjufg"
        "a76g0cm7h9mfb5mghfsdpagdbpdjppsusuhxg6mjmsdbs8wnqqnxhn4jebk1ki1ud53rw1w00");
    checksum.push_back("b5f0tip4");
    address.push_back(
        "frxf6jy66qrdyw0rhdf25qyhambcj97qq9g8yb2en8b4ehs0h3tie6cwa3p58hdgigwjttf56nt8qra83efjbd6dhexgnqjjfg4wa1wgm7t291"
        "8m789jush9ca00k8kp4m2e96hfgqbtbderjpb1pe8js9mf4awrid5ikp8hsqqqpuf6w23t6rk");
    checksum.push_back("cd0d4drr");
    address.push_back(
        "515a87pbbtp5ujhuyytrjfbgyi1y3gy3d08r6mpin4eqp12ctfgsftbjwtddbucwt8hb4dsg18w8i7fr9wmmjexjpk4qpjfjjdde0jcu740em1"
        "h2ui208ksgm12pfantkg6uuy7790wk00mdwhq8ch0wckt84ck7diyk34majh08tg34nmatrak");
    checksum.push_back("d3w81u56");
    address.push_back(
        "a39x5m1dr874fra4dmrfm25iysmk7dryrrgeancf5mat0j45b8xt67fudfadar2kjnyw1jijejiw8rryr7s31suyre31dwftwxr52kt1nj3wek"
        "20nmujmiac4nb0m56txk04u68a1e130irg4bffd43pswsdpgkca44gcauji5pp14yuhcpmhhx");
    checksum.push_back("rpbe2cum");
    address.push_back(
        "38pq92mtm3kk02h0m62d3q0qgwebmsisx3sj2j1ai0298ng6yajq0kdcqb0jhgbwme66py9tw2icjrwsqm8xa8idk8ph3nt26j58erakc3akgn"
        "e3wasugm6ib6ha91sw3j9sfy3ddsqpth8cm4xw3bqqgipp9t9s8htr957x7crt7wt342nnfbx");
    checksum.push_back("bgnexda6");
    address.push_back(
        "1fidgqmk50r59k91y8r50wa75m7t9r5j15y7ywfrekt6kqrj0sfr10646u2er5qkt011jhx1b95mj5frbfe6pb80xggs3wep64jw8xu4embit1"
        "uid0ch145rtukj82kfjxdum4x5bcacwcxdgmdhiwnrhisw5xf0smuryc0tscbi5s3tgiw4pm0");
    checksum.push_back("etk6xin9");
    address.push_back(
        "rrbmapchcgq095y9r65k6ta4q9sxsj2e44x64rpdca11wcp66mn9bf6gmjuybtspfg1fqc9at4mht4begemjcx21i176kxd81etna2tdpub5hb"
        "kbbnen0tyymctbm3spd2d6pba46jegf5ynu0wugmakc4857jpg8cu7enug20iwa3wigyswig2");
    checksum.push_back("2p9tuswp");
    address.push_back(
        "09f5wyn8180si5egmm7txipaxxhg4nemnb668yx9t4x752xgrqhq45sxsxmdpa7wur78smhyh6r76676aqim83xb7tewhe7wk4wg0ijjc20q4g"
        "betuubkmyhr1mt0x3jbryss8b3kw2i6u14ccs6r2c22dfnekw230y30u0bj5c6msekbfd3en2");
    checksum.push_back("mx6pw5ma");
    address.push_back(
        "1xh7g0ntien7x118tsapb43yh7peryr474y6sscpd6tqap7dq9ebhj9kd306wnh3ttdnc79d1905p8y3pnt26m7fks7kd516btqmgng9ehj48r"
        "x7r5msbfmr9uapga085666x3udky7jyqtm7wdh8wk9ei1wep0gxy26cx12g25mqy4b1a1ti70");
    checksum.push_back("6q794hbh");
    address.push_back(
        "3gbej7xyf4ks636y085y8tyqhmqgqcjxj5x2s0f48dynb3jnfhy1agn5twuwa31d454i2gx4saimiy1k0pt2eurxtd6xua9upr0mdxtiqmq9gd"
        "f08qu3feet3ac1jqaq5ar68kt8f70jqr3nf7q92id5e60bb0050efa4snwyiuku21725tgy30");
    checksum.push_back("kiq5q9nw");
    address.push_back(
        "8dug6pnn6pmkmna106wrhk2u2cnsnm25i2faejh1a8xg2kw78xpewyhr3sma6ry200i1j0t9is5rsbr2wgfmgt2s9gxu05bh1mhy4q9b5jqmje"
        "sgftckyhmunpwe6h225qb5pcp8r00fkiaby81d5ngtgiabciauaehmj27iq3qd0cimiyncf9k");
    checksum.push_back("ebx0bixr");
    address.push_back(
        "6yuxa3ur12ctu3pqf007g69uwxhkx4hqp8nq08qb69hp0p4m639m9hwf7xm7503xtbyrd3ck7rabma7dtbbcjbu6qgt6uk4kr3a66fp0jn99eb"
        "nyjc7t40ybyumjgtbnad32grp8rkhbdkk2sn6je0k1hw3w1r1u337rth1a3nimx0etqfmgp52");
    checksum.push_back("kmsd10ug");
    address.push_back(
        "03t1hmft08bb48ddjm9b3a7frb6r0kpus5ps0m337wr1f68y4mimrh4mhn6c8tiuajfgprr6idwqdii7tqxd836acj7brtyp2fh30jmdku60a1"
        "00feu11kurjjjw79ii4anpxgpjc768bejkrjt6uf9hsmrxiyf674gq06wi86ewe41rnc4qm60");
    checksum.push_back("dsyg7a5t");
    address.push_back(
        "p381iuedq0a6ykki5a10pe9e11d26ngbyxyybwmkawq4etatmwyewg291ip8x343dhb44cbhftfgkgadu54fef3b026e831x6dr5e934uj0cuk"
        "rnh1ikiqqwf1pmghh2b91jwu4sqpdfw1s9sh0smmusrwbn354j0ewetwdw0m8rknhkr4mm580");
    checksum.push_back("ue2f6tf5");
    address.push_back(
        "h0c6i990unfgtcrpj9qi5r5hw9i073w0bfetn6nrk7u5kh7me66t7xf4akmcgeqms95bggibpai8pcq1hp1fph5gq54a6y8cnk33asjbn3q4u9"
        "niakw0ks4rgbkgg9g3es1j6ti364kcf466805hb098eexk8fs43qti36j58pbggtidrqkcdak");
    checksum.push_back("wx7x7fkn");
    address.push_back(
        "hckatc95ga32qn38sjp0d6fq948pw27bi5fjx4tqpqqgap3y05jdm8nafje7ma88cad1iu0bcguufa20befby3pf26khr2cpcc2br02wtwfwwf"
        "briqpy82kretqctym9wadps1k214nrwt4t3qw4nc6a3eehmuqqmh9b923ab6uykqwe58x6b60");
    checksum.push_back("mhwujk3n");
    address.push_back(
        "kd35c12r3r8ckmiwtcuba6c549i2k5aa4yhjcarqibn36bxxnejb2hp1n4cdnm8r0qswp01e2rywnfswkfhj6e357u2rtutaq531pie5t33r3t"
        "842bchb4wa2f3dssyqyih6ys84rk3hw59euuk7camhf3smpry26e84k1knrgh77b4k9tjh3w0");
    checksum.push_back("09jmncnt");
    address.push_back(
        "01bs9gtm6c9bwie134yiq28p3611r32dwh27aeewubns1kdmthx6amj1grr53c1chhuyqmr7ytk7fcs86neufts4wpf24tk9c9hrgx12rh8u71"
        "b55kejjx7s7dh17ctnup9kwr9uw4pr5tq0rf71u46b2s6303mw10kt5bpkxhbqa51neturfyk");
    checksum.push_back("2n13m2e4");
    address.push_back(
        "31g4whbake2frh0eiwuhaiw4ikk5pbd0ywuwp7jcq3rb7mdq314dwy36s8y44n7d0ipbshj8dracwag1pig6syi9hk2dah8gtm7wr6qfeshc1t"
        "tts4nu0cubrp64ptrbjpmxghd911767k5e8wdsx2d4mw5q87c9ftymp7tq508ipy8rxus3qnx");
    checksum.push_back("gqh062uk");
    address.push_back(
        "1xifgirqgf8kbiebu7enuag1iea5xkt63p2ejq9e7yxyapmurc7pgyi3f0huqaf414q42p5hps99rikm1ta52c8u4mwqfdc6p9dgkjcy2trdwr"
        "619gsmuj5yp48es5dqsd7pf37uyad606x5u16iuc3yauq3ixwmcucgg7cn4bar40m3r0hr8m2");
    checksum.push_back("ry1t3ita");
    address.push_back(
        "k9qf21i1acp0mh6aab95ckjc79e6jcpfk82ua21kffyc3162twpa5wjb4jjfr7s9abw9b7sask0kwywc392ps3g3b5s9et1ptp3e695s6kfcqc"
        "u76tmgy2ttwtgy1ik2r55g9f0gqb3bty9mmyhwc98edi8857cbk3qfjue3j8anctca3yt65c0");
    checksum.push_back("34bcm2pd");
    address.push_back(
        "6qcfnpftj06xw4xm2aywhgc9mk8naw1xbhjxggcqrds273rx3xtfyysqwup66j6jx1crds9agc4uctbqn09jpf3xykytw75bf7kx42ssjj035p"
        "dec4wb303hfykecbn85ym6hsch0tnp7is636hwr965cck4art12xt4g3c79cbfcqgjen2q4ik");
    checksum.push_back("wy0237sy");
    address.push_back(
        "fi99i4q5h0mua5j8aasq98abtr7y1rc19afn193xhm2qk9hwuucipskp0jp1um7si9n5y9ycaffipyph6dbcb4wek2wf5tafmebwrnrh60i8d4"
        "dcerf7i50equnb834j4q985sjqbs1phu7xtta4tgkbfiiq030y1kh8j8w1a1ygtt1x1gwybnk");
    checksum.push_back("y5n9ptfe");
    address.push_back(
        "t1cuj966mcss7btsjd6uway5t5k4ixq7g47yrqp1xwyep3rcpupitbna8my0p3h5yyng1eskncc1b4c3k4eg1q6hxu3b9rnq0jjit6hkkxkh9r"
        "uubty4mhis0uqp0inkj570apn477p6i9ufe0h0ngfk3k3cb09idpy70j55p5r5b662xcek9pk");
    checksum.push_back("e2579by4");
    address.push_back(
        "na24atd75jrd7pwyaex6xa2ut20tqcp8ufwe35a7qhgjwa694266y0aefxpkhtnabwrwcu02c5t6mmqj4a7bxh49gixret9a6rwy6hx7g4b88g"
        "9yi8j251ib5dirnywnpj5mkwgm8n5f1ubni41jsexkxgy01w9d0nn3ke1w554qwq58atef5g0");
    checksum.push_back("5i93nfha");
    address.push_back(
        "1ahqmm123gtc0aewyawg4me4ibidqqxuisyhwr4wr04eh8yy5i6h5yu41b9pjmk69y82fa1njari4262r1gnr3q9brk0t7qbirit6h2xcwumbr"
        "72cmf0sp4mu6thy31bwhmqa83cytndbq0si3ikpjxdfxgdeqqr5hibf9t0wgnxx0kyy5qrkp2");
    checksum.push_back("xeq5gptm");
    address.push_back(
        "0h9b7pti709e0x8ec9a8kuns9e1tf7fm7bc6d0mb3ffhdkg2u054sxshkghkwfb1tr4d0shhyxrrkqf1emgjnsb9eauruexgds6w2ujwi7nxwr"
        "mun1agbgguugmifakqqwxke3iuxfn3qsfb0wu5fknyj2asmqxafb2cawe2rd65j7aaiw7gia0");
    checksum.push_back("xhwp6grk");
    address.push_back(
        "sihtwbcgmfj3metpwiubryk4t6bakb6k25pbu7tiui2gxmcnpxmt3ymb7ushp8gcybirbpmpkckwt3nputtifwyb5a2rh7ytpy5rk0pb4xi5ub"
        "gr61m3unup4ebhi602qn4gj0mcf9pyp5d9nq9xtx67acxs6chpru0k7x5nq5wqi9r7k0kwhmx");
    checksum.push_back("w5frsjkd");
    address.push_back(
        "uxyqxintnmue5qrm2479ysdekcbiund4m0m8u8jjp15wagcpkqq50spp65xdyc2jjwfjfh223d36jcar0g8s8fj9ru2gcd507s64g1cs11xnka"
        "e25n426xx22p0umjdse5srtm0rncd8f42s2u6s2sey3c7yptxjwysxt5yng7k61ph3g21xm5x");
    checksum.push_back("bruh0iey");
    address.push_back(
        "3dgcsqnre69sfn6ps7wyf1619tbtt5g41p3tp7hrm2635dnd7burearfq0cmxjmt0fwt0nyp78ru2u61crd60mg3i35bfks8e3xekwq30c7p7b"
        "ga21dbqd80fww4559c8425f0ma1wph6i3ef4y369k5ryr83rs9qnf113ief9gct3y0dcnp6b2");
    checksum.push_back("13phrn1e");
    address.push_back(
        "stqpr9mxf5yaa6adtenafe108eatx9nybx4qjdtqa37fcekpq14i0ux2i9qt4hhhceay2582p9pmg412atpq2mwxkq470wf8rddx82jggcemnd"
        "d774hkpuuk3jkkunx57bfphgmteahr1bgkyh54f0uqrybsdcinkj7wck3r5iferp1969q32m0");
    checksum.push_back("iabynpih");
    address.push_back(
        "aqs262h38tn5maje810gr8rr4wc5tstf97c89wk0c4qfwy5kngj8drncfjdphkdf27dsih75bx56npc21t091c6wgi1045pnyp4m4kepshj7he"
        "yaw3yfu8pc9614kmj1cwf4dg1bsc5qwqk80mcs15byejksj9nat37emst881spg4mnubnb38k");
    checksum.push_back("akwabkx5");
    address.push_back(
        "sjyjdq4b1eds2a6yufsy91mhxej1et5xs002wgfjdbxj51ccn65t448yr0r8pfmwyme29tusemd064xruyn5fa8i4taqccsa0swsiyk8h43154"
        "4nmnnc827yubu763mj7pdftbiip5a5tnud88n2fsf1st3w5tsceqh3ye0esyyjj82a3csfh2x");
    checksum.push_back("hpn6gwdy");
    address.push_back(
        "596g35cwe8e1p6089qkrtd5umf06b0ntuhr2q2uryn11xqnd5mm9ijckqtc9y175ypf7k2xhm0e2f09ehmd2ixyrqbm2fap7yp8fec1qpaymqy"
        "mqe7yi5tcc55s6q3i7cguk9tsgn1nwwhaciy1q28tnef8ab0ypbe79e6cd5j3mkj3u6emb0mx");
    checksum.push_back("m3rktw9g");
    address.push_back(
        "fceb6xbspiipgea4b81e71sak157t6c3kaa1y51nw87hc3dbq4542hng8q41mi32pp0kcsaf5kqp0686mefkyqbh1adwdrmrgf5bkaaiic9b9a"
        "5pfuu8xi57rm294s3tr2yiju9hq1trudu2kniurku9f3b0p7cs9ubj35pcmapr9jwqahidwg2");
    checksum.push_back("xd1ri23w");
    address.push_back(
        "ycxjqfdf09ttbi70qp10s0e48b6phetrcmawj86sykpfxj686sp0kwehny8w0jki5cdu82m6i5rsjbiccne6yu0q3c6rcr7qf9hr8sfx8qbx0t"
        "6fhir7dsteiyrstfswhjc217w27wnhyr90b1q80imed8sp21nr398j6bffkiam2kgx98uuu42");
    checksum.push_back("ny7b9p29");
    address.push_back(
        "pbu4u10ic5xq3i8m041ckj93hin8gty4p22y52cy939wag2s4g7nkbq769nanhykygq3mmigx1gttjw51rt9t897gj9692kyynnh0k864266ap"
        "x2wre9i4ymias24ndsbfywjffhbkn1ehkbgcx0wqincygjqsqe2t4p71gy8q1pek2c9pqq0f2");
    checksum.push_back("9wxwca0p");
    address.push_back(
        "cmcj2511f37mjenygp1jwnm9bcni8dkccw8pwcf485r2i8wn8r0bmprjsnw6gfk9jxrkbxbjk3kanxttfrk4u53akwtcenhjet8q8mybyyy2db"
        "me2jugqjt5da4h97kprh00twxqypmk2c9a8est4349ih5tsbdcrdfkace295i3kcx3qq0yje0");
    checksum.push_back("52uidfm6");
    address.push_back(
        "0ty8hbeewfe2tdb36bu1gsd800trypqywgq0kc1y61waw4e7pbiyc4y9dfsd9nyaqitjn8afjgby1844ud0ichepq7ndjm9cdxkag3qbafsted"
        "thnnqgd06a8earhg0794j9mwik9msmwbe52jpihbabc92qx7cfeuscp2urufy2bi6k3qucnw2");
    checksum.push_back("y7ydf7jm");
    address.push_back(
        "ee3q92cjh6j79be8k9s6dqqe6t15i59q9eu5eyq97wdk25psty8ftysuns8wumwtdh91phy76ykf37mu2nywfiq6fq50rsek4h4upmikwdy98h"
        "qyws8k237m9is40gkprf1ci0nf43jkhnm8mxr1uk38d2pycuiff7ghh5fxj0hi35hs798aif0");
    checksum.push_back("nyfcyf52");
    address.push_back(
        "tw0r0u3j13syy01sguyssddusciw9ie9skjhqj2dwtk9d5x7da2ss8s11t247bkfqhibannuu2xwbj4ny0tckxp7pmi42jry6fcrkedwmh1umm"
        "sgmt9xp0w4hb4s6yb2bah7gswx1dta3q86ibquj2b0di8ne6sn0g4cqatc6ymj2na3fwtp13x");
    checksum.push_back("jqhqtsr6");
    address.push_back(
        "qeswe3gumw2kftntg0watnf75wef0sneijnjr456eqgs8j855k0psf1wkfu0uq4x7btismp27a9sfdk237jwmjxt1hqxy93hcbejempxxsjx0w"
        "8ruf3hr0w9tkuharxhq6bxpe9im9jh1465us8djxdej7muy8cjtnxrh6ync8tupmr07wwckgx");
    checksum.push_back("cxbf3ddc");
    address.push_back(
        "e6d6usrugwbj1i4q4j6xy41ic1pna7n6re0hbcbibjdxcjsd7kccxhupht7hncrgxc0xmyf6wra6rui94kf73ih40382wrmxu72g2njptur45k"
        "pgah7511ch8k97srep2eytg4jepau2204u6r2a5a83mwrh34gimc17khjsqspa80y7em1tn1x");
    checksum.push_back("5tsnq3pk");
    address.push_back(
        "f1t1kgtm9ijrh5b5f7bndk59k3jy5xbm2ujn0hkrrbjuxc040rxp3swratihgdu9w47u5wk66by0cnd5js30tprgmsuafy5dp8m88uw7b5rq6g"
        "s4ju82sade26hbbn29sk4qtnjfpd87xij153cd68k4mr34qu9893gek6ei513pwbu4mu5e8pk");
    checksum.push_back("8c2773qx");
    address.push_back(
        "x2cfdktkj5tqap9c3u98yf8j0hu1737i15mqiyraqys37mg3qyf2uffet6680csw9724kksdymcfgswpfjap8wb53naf3w4d0a9rdc8xubh2k4"
        "3sc4rts6sjtu0in6qe88i7s12w431fu54r01qf4cdrrrpecbnu571wk57xyb4s0e7xgcafchx");
    checksum.push_back("07209mj7");
    address.push_back(
        "7ap4h46iweah0dmisbm222nnyyff968ydr9aqhn5kunxiqiyftfn75qbq09x9gfdpgye3pmpwqhcfniwk8p51dtwey7ek837cfjewxwywp9w7f"
        "2c996nea7eqde59emshw3sn94i76rdkp024rbttynmbi4r4sn9a27cp2d2xn7g130fg270by0");
    checksum.push_back("bp9np49b");
    address.push_back(
        "37kn6fef8kj16u62w49xi3ajpxnptk7ra7j6t2cm623bwj4raddqwf1tp7hmap47n7gsiihj00iihdpugck09mk7nwmw18fgagp3aw4t4c2ptb"
        "in0j13ad63318idifyhpuus7bfbf1pswe1cbx3cf0wr35qne5e8wkhd7808q6bfjqswujdrp2");
    checksum.push_back("dgy88si3");
    address.push_back(
        "ykh8f552s79uhk8tnqx56hsknxerfk2pxn2q6jbef07626m2qgeht3c8ry2kdjab7rr38tsbt668c3dt8nuirb3sprjmkhn3ydhcetatk0dfg0"
        "fxpkgcpm8hyu0b7ds14a2gfty95jmu4r3qeqmtjw8pg6yhh97icdke49rkhj65i755xpguxhx");
    checksum.push_back("7c754hqd");
    address.push_back(
        "8669a14n68kbb6gt3uhpi8c6i4rhws3g6d0cwyhfus1ghbg51uqraqwb15y2g1b23d3pf2w18c1s8tysqwtg2grnyidc65n428bwd1i3j9abs7"
        "pnais6gd1qgn2gguj53r2cnkjx47tk0iapsedn27u9san1duj66ukgrcbc9r6ud6h932mtakx");
    checksum.push_back("jyi767dp");

    do_test_checksum_vector(address, checksum);
}