#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <map>
#include <vector>
#include <set>
#include <string>

struct keyword {
    // Text being matched
    const char* text;
    // True if match is case insensitive
    bool insensitive;
    // Output token
    const char* token;
};

struct matchnode {
    const char* token = nullptr;
    const char* text = nullptr;
    std::map<matchnode*,std::vector<char>> children;
};

void genmatchnode(matchnode* node, const char* prefix, int textlen, const keyword* table) {
  // Identify all possible next chars
  const char* outtoken = NULL;
  const char* outtext = NULL;
  std::map<char, std::vector<const keyword*>> nexts;
  int prefixlen = strlen(prefix);
  assert(prefixlen <= textlen);
  for (const keyword* i = table; i->text != NULL; ++i) {
    if ((int)strlen(i->text) != textlen)
      continue;
    if (i->insensitive ?
        (strncasecmp(prefix, i->text, prefixlen) == 0) :
        (strncmp(prefix, i->text, prefixlen) == 0)) {
      if (prefixlen == textlen) {
        if (outtoken != NULL) {
          fprintf(stderr, "output token %s is redundant with %s\n", outtoken, i->token);
          exit(1);
        }
        outtoken = i->token;
        outtext = i->text;
      } else {
        char c = i->text[prefixlen];
        nexts[c].push_back(i);
        if (i->insensitive) {
          if (c >= 'a' && c <='z')
            nexts[c + ('A' - 'a')].push_back(i);
          else if (c >= 'A' && c <='Z')
            nexts[c + ('a' - 'A')].push_back(i);
        }
      }
    }
  }
  if (outtoken != NULL) {
    if (!nexts.empty()) {
      fprintf(stderr, "output token %s is a prefix of another keyword\n", outtoken);
      exit(1);
    }
    node->token = outtoken;
    node->text = outtext;
  } else {
    std::map<char,matchnode*> children;
    for (auto& i : nexts) {
      // Look for duplicate output states
      bool found = false;
      for (auto& j : nexts) {
        if (i == j)
          break;
        if (i.second == j.second) {
          found = true;
          children[i.first] = children[j.first];
          break;
        }
      }
      if (!found) {
        // Recurse
        matchnode* newnode = new matchnode;
        children[i.first] = newnode;
        char newprefix[prefixlen+2];
        memcpy(newprefix, prefix, prefixlen);
        newprefix[prefixlen] = i.first;
        newprefix[prefixlen+1] = '\0';
        genmatchnode(newnode, newprefix, textlen, table);
      }
    }
    // Reverse the map to make later analysis easier
    for (auto& i : children)
      node->children[i.second].push_back(i.first);
  }
}

void genchaincode(std::vector<matchnode*>& chain, unsigned prefixlen, FILE* fd) {
  for (unsigned j = 0; j < chain.size(); ) {
    if (j > 0)
      fprintf(fd, " && ");
    auto* n = chain[j];
    auto& chars = n->children.begin()->second;
    
    if (chars.size() > 1) {
      fprintf(fd, "(");
      bool first = true;
      for (char c : chars) {
        if (first)
          first = false;
        else
          fprintf(fd, " | ");
        fprintf(fd, "(keyw[%u] == '%c')", prefixlen+j, c);
      }
      fprintf(fd, ")");
      ++j;

    } else {
      // Optimize case where we are matching a sequence of single characters
      unsigned k;
      for (k = 1; k < 8 && j+k < chain.size(); ++k) {
        if (chain[j+k]->children.begin()->second.size() != 1)
          break;
      }
      if (k == 1) {
        fprintf(fd, "keyw[%u] == '%c'", prefixlen+j, *chars.begin());
        ++j;
        
      } else {
        // Match up to 8 characters at once
        unsigned long pattern = 0;
        for (unsigned l = 0; l < k; ++l)
          pattern |= ((unsigned long)(unsigned char)*chain[j+l]->children.begin()->second.begin())<<(l*8);
        if (k == 8)
          fprintf(fd, "(*(unsigned long*)&keyw[%u] == 0x%lXUL)", prefixlen+j, pattern);
        else
          fprintf(fd, "((*(unsigned long*)&keyw[%u] & 0x%lXUL) == 0x%lXUL)", prefixlen+j, (1UL<<(k*8))-1, pattern);
        j += k;
      }
    }
  }
}

void gencode(matchnode* node, unsigned indent, unsigned prefixlen, FILE* fd) {
  auto doindent = [&indent, fd](){
    for (unsigned i = 0; i < indent; ++i)
      fputc(' ', fd);
  };

  // Create a chain of nodes with a single possible transition. These
  // are optimized with a single if statement.
  std::vector<matchnode*> chain;
  matchnode* end = node;
  while (end->children.size() == 1) {
    chain.push_back(end);
    end = end->children.begin()->first;
  }
  if (!chain.empty()) {
    doindent();
    fprintf(fd, "if (");
    genchaincode(chain, prefixlen, fd);
    fprintf(fd, ") {\n");
    indent += 2;
  }

  doindent();
  if (end->token != nullptr)
    fprintf(fd, "return %s; // \"%s\"\n", end->token, end->text);
  
  else {
    fprintf(fd, "switch (keyw[%lu]) {\n", prefixlen + chain.size());
    for (auto& i : end->children) {
      for (char c : i.second) {
        doindent();
        fprintf(fd, "case '%c':\n", c);
      }
      gencode(i.first, indent+2, (unsigned)(prefixlen + chain.size() + 1), fd);
      doindent();
      fprintf(fd, "  break;\n");
    }
    doindent();
    fprintf(fd, "}\n");
  }

  if (!chain.empty()) {
    indent -= 2;
    doindent();
    fprintf(fd, "}\n");
  }
}

void genmacros(const keyword* table, const char* funname, const char* errtoken, FILE* fd) {
  unsigned j = 0;
  std::set<std::string> done;
  for (const keyword* i = table; i->text != NULL; ++i) {
    if (done.count(i->token) == 0) {
      fprintf(fd, "#define %s %uL\n", i->token, j++);
      done.insert(i->token);
    }
  }
  fprintf(fd, "#ifndef %s\n", errtoken);
  fprintf(fd, "#define %s -1L\n", errtoken);
  fprintf(fd, "#endif\n");

  fprintf(fd, "long %s(const char* keyw, unsigned long keyw_sz);\n", funname);
  fprintf(fd, "const char* un_%s(long id);\n", funname);
}

void genmatcher(const keyword* table, const char* funname, const char* errtoken, FILE* fd) {
  std::map<int,matchnode*> rootsbylen;
  for (const keyword* i = table; i->text != NULL; ++i) {
    int len = strlen(i->text);
    if (rootsbylen.count(len) == 0) {
      matchnode* root = new matchnode;
      genmatchnode(root, "", len, table);
      rootsbylen[len] = root;
    }
  }
  
  fprintf(fd, "long %s(const char* keyw, unsigned long keyw_sz) {\n", funname);
  fprintf(fd, "  switch (keyw_sz) {\n");
  for (auto& i : rootsbylen) {
    fprintf(fd, "  case %d:\n", i.first);
    gencode(i.second, 4, 0, fd);
    fprintf(fd, "  break;\n");
  }
  fprintf(fd, "  }\n");
  fprintf(fd, "  return %s;\n", errtoken);
  fprintf(fd, "}\n");

  fprintf(fd, "const char* un_%s(long id) {\n", funname);
  fprintf(fd, "  switch (id) {\n");
  for (const keyword* i = table; i->text != NULL; ++i) {
    fprintf(fd, "  case %s: return \"%s\";\n", i->token, i->text);
  }
  fprintf(fd, "  }\n");
  fprintf(fd, "  return \"???\";\n");
  fprintf(fd, "}\n");
}

void gentest(const keyword* table, const char* funname, const char* errtoken, FILE* fd) {
  fprintf(fd, "void test_%s() {\n", funname);
  for (const keyword* i = table; i->text != NULL; ++i) {
    char scratch[1024];
    strncpy(scratch, i->text, sizeof(scratch));
    fprintf(fd, "  assert(%s(\"%s\\0\\0\\0\\0\\0\\0\\0\", %lu) == %s);\n",
            funname, scratch, strlen(scratch), i->token);
    if (i->insensitive) {
      for (char* p = scratch; *p != '\0'; ++p) {
        if (*p >= 'a' && *p <= 'z')
          *p += 'A' - 'a';
      }
      fprintf(fd, "  assert(%s(\"%s\\0\\0\\0\\0\\0\\0\\0\", %lu) == %s);\n",
              funname, scratch, strlen(scratch), i->token);
      for (char* p = scratch; *p != '\0'; ++p) {
        if (*p >= 'A' && *p <= 'Z')
          *p += 'a' - 'A';
      }
      fprintf(fd, "  assert(%s(\"%s\\0\\0\\0\\0\\0\\0\\0\", %lu) == %s);\n",
              funname, scratch, strlen(scratch), i->token);
    }
    auto textlen = strlen(i->text);
    strncpy(scratch, i->text, sizeof(scratch));
    scratch[textlen] = 'x';
    fprintf(fd, "  assert(%s(\"%s\\0\\0\\0\\0\\0\\0\\0\", %lu) == %s);\n",
            funname, scratch, strlen(scratch), errtoken);    
    strncpy(scratch, i->text, sizeof(scratch));
    scratch[textlen-1] = '\0';
    bool found = false;
    for (const keyword* j = table; j->text != NULL; ++j) {
      if (i != j && strcmp(scratch, j->text) == 0) {
        found = true;
        break;
      }
    }
    if (!found)
      fprintf(fd, "  assert(%s(\"%s\\0\\0\\0\\0\\0\\0\\0\", %lu) == %s);\n",
              funname, scratch, strlen(scratch), errtoken);
    for (unsigned j = 0; j < textlen; ++j) {
      strncpy(scratch, i->text, sizeof(scratch));
      scratch[j] = '|';
      fprintf(fd, "  assert(%s(\"%s\\0\\0\\0\\0\\0\\0\\0\", %lu) == %s);\n",
              funname, scratch, strlen(scratch), errtoken);
    }
  }
  fprintf(fd, "}\n");
}

int main(int argc, char** argv) {
  static const keyword json_table[] = {
    { "jsonrpc", false, "KEYW_JSON_JSONRPC" },
    { "id", false, "KEYW_JSON_ID" },
    { "method", false, "KEYW_JSON_METHOD" },
    { "params", false, "KEYW_JSON_PARAMS" },

    { "bytes", false, "KEYW_JSON_BYTES" },
    { "commitment", false, "KEYW_JSON_COMMITMENT" },
    { "dataSize", false, "KEYW_JSON_DATASIZE" },
    { "encoding", false, "KEYW_JSON_ENCODING" },
    { "epoch", false, "KEYW_JSON_EPOCH" },
    { "filters", false, "KEYW_JSON_FILTERS" },
    { "identity", false, "KEYW_JSON_IDENTITY" },
    { "length", false, "KEYW_JSON_LENGTH" },
    { "limit", false, "KEYW_JSON_LIMIT" },
    { "maxSupportedTransactionVersion", false, "KEYW_JSON_MAXSUPPORTEDTRANSACTIONVERSION" },
    { "memcmp", false, "KEYW_JSON_MEMCMP" },
    { "mint", false, "KEYW_JSON_MINT" },
    { "offset", false, "KEYW_JSON_OFFSET" },
    { "programId", false, "KEYW_JSON_PROGRAMID" },
    { "rewards", false, "KEYW_JSON_REWARDS" },
    { "searchTransactionHistory", false, "KEYW_JSON_SEARCHTRANSACTIONHISTORY" },
    { "transactionDetails", false, "KEYW_JSON_TRANSACTIONDETAILS" },
    { "votePubkey", false, "KEYW_JSON_VOTEPUBKEY" },

    { "getAccountInfo", false, "KEYW_RPCMETHOD_GETACCOUNTINFO" },
    { "getBalance", false, "KEYW_RPCMETHOD_GETBALANCE" },
    { "getBlock", false, "KEYW_RPCMETHOD_GETBLOCK" },
    { "getBlockCommitment", false, "KEYW_RPCMETHOD_GETBLOCKCOMMITMENT" },
    { "getBlockHeight", false, "KEYW_RPCMETHOD_GETBLOCKHEIGHT" },
    { "getBlockProduction", false, "KEYW_RPCMETHOD_GETBLOCKPRODUCTION" },
    { "getBlocks", false, "KEYW_RPCMETHOD_GETBLOCKS" },
    { "getBlocksWithLimit", false, "KEYW_RPCMETHOD_GETBLOCKSWITHLIMIT" },
    { "getBlockTime", false, "KEYW_RPCMETHOD_GETBLOCKTIME" },
    { "getClusterNodes", false, "KEYW_RPCMETHOD_GETCLUSTERNODES" },
    { "getConfirmedBlock", false, "KEYW_RPCMETHOD_GETCONFIRMEDBLOCK" },
    { "getConfirmedBlocks", false, "KEYW_RPCMETHOD_GETCONFIRMEDBLOCKS" },
    { "getConfirmedBlocksWithLimit", false, "KEYW_RPCMETHOD_GETCONFIRMEDBLOCKSWITHLIMIT" },
    { "getConfirmedSignaturesForAddress2", false, "KEYW_RPCMETHOD_GETCONFIRMEDSIGNATURESFORADDRESS2" },
    { "getConfirmedTransaction", false, "KEYW_RPCMETHOD_GETCONFIRMEDTRANSACTION" },
    { "getEpochInfo", false, "KEYW_RPCMETHOD_GETEPOCHINFO" },
    { "getEpochSchedule", false, "KEYW_RPCMETHOD_GETEPOCHSCHEDULE" },
    { "getFeeCalculatorForBlockhash", false, "KEYW_RPCMETHOD_GETFEECALCULATORFORBLOCKHASH" },
    { "getFeeForMessage", false, "KEYW_RPCMETHOD_GETFEEFORMESSAGE" },
    { "getFeeRateGovernor", false, "KEYW_RPCMETHOD_GETFEERATEGOVERNOR" },
    { "getFees", false, "KEYW_RPCMETHOD_GETFEES" },
    { "getFirstAvailableBlock", false, "KEYW_RPCMETHOD_GETFIRSTAVAILABLEBLOCK" },
    { "getGenesisHash", false, "KEYW_RPCMETHOD_GETGENESISHASH" },
    { "getHealth", false, "KEYW_RPCMETHOD_GETHEALTH" },
    { "getHighestSnapshotSlot", false, "KEYW_RPCMETHOD_GETHIGHESTSNAPSHOTSLOT" },
    { "getIdentity", false, "KEYW_RPCMETHOD_GETIDENTITY" },
    { "getInflationGovernor", false, "KEYW_RPCMETHOD_GETINFLATIONGOVERNOR" },
    { "getInflationRate", false, "KEYW_RPCMETHOD_GETINFLATIONRATE" },
    { "getInflationReward", false, "KEYW_RPCMETHOD_GETINFLATIONREWARD" },
    { "getLargestAccounts", false, "KEYW_RPCMETHOD_GETLARGESTACCOUNTS" },
    { "getLatestBlockhash", false, "KEYW_RPCMETHOD_GETLATESTBLOCKHASH" },
    { "getLeaderSchedule", false, "KEYW_RPCMETHOD_GETLEADERSCHEDULE" },
    { "getMaxRetransmitSlot", false, "KEYW_RPCMETHOD_GETMAXRETRANSMITSLOT" },
    { "getMaxShredInsertSlot", false, "KEYW_RPCMETHOD_GETMAXSHREDINSERTSLOT" },
    { "getMinimumBalanceForRentExemption", false, "KEYW_RPCMETHOD_GETMINIMUMBALANCEFORRENTEXEMPTION" },
    { "getMultipleAccounts", false, "KEYW_RPCMETHOD_GETMULTIPLEACCOUNTS" },
    { "getProgramAccounts", false, "KEYW_RPCMETHOD_GETPROGRAMACCOUNTS" },
    { "getRecentBlockhash", false, "KEYW_RPCMETHOD_GETRECENTBLOCKHASH" },
    { "getRecentPerformanceSamples", false, "KEYW_RPCMETHOD_GETRECENTPERFORMANCESAMPLES" },
    { "getRecentPrioritizationFees", false, "KEYW_RPCMETHOD_GETRECENTPRIORITIZATIONFEES" },
    { "getSignaturesForAddress", false, "KEYW_RPCMETHOD_GETSIGNATURESFORADDRESS" },
    { "getSignatureStatuses", false, "KEYW_RPCMETHOD_GETSIGNATURESTATUSES" },
    { "getSlot", false, "KEYW_RPCMETHOD_GETSLOT" },
    { "getSlotLeader", false, "KEYW_RPCMETHOD_GETSLOTLEADER" },
    { "getSlotLeaders", false, "KEYW_RPCMETHOD_GETSLOTLEADERS" },
    { "getSnapshotSlot", false, "KEYW_RPCMETHOD_GETSNAPSHOTSLOT" },
    { "getStakeActivation", false, "KEYW_RPCMETHOD_GETSTAKEACTIVATION" },
    { "getStakeMinimumDelegation", false, "KEYW_RPCMETHOD_GETSTAKEMINIMUMDELEGATION" },
    { "getSupply", false, "KEYW_RPCMETHOD_GETSUPPLY" },
    { "getTokenAccountBalance", false, "KEYW_RPCMETHOD_GETTOKENACCOUNTBALANCE" },
    { "getTokenAccountsByDelegate", false, "KEYW_RPCMETHOD_GETTOKENACCOUNTSBYDELEGATE" },
    { "getTokenAccountsByOwner", false, "KEYW_RPCMETHOD_GETTOKENACCOUNTSBYOWNER" },
    { "getTokenLargestAccounts", false, "KEYW_RPCMETHOD_GETTOKENLARGESTACCOUNTS" },
    { "getTokenSupply", false, "KEYW_RPCMETHOD_GETTOKENSUPPLY" },
    { "getTransaction", false, "KEYW_RPCMETHOD_GETTRANSACTION" },
    { "getTransactionCount", false, "KEYW_RPCMETHOD_GETTRANSACTIONCOUNT" },
    { "getVersion", false, "KEYW_RPCMETHOD_GETVERSION" },
    { "getVoteAccounts", false, "KEYW_RPCMETHOD_GETVOTEACCOUNTS" },
    { "isBlockhashValid", false, "KEYW_RPCMETHOD_ISBLOCKHASHVALID" },
    { "minimumLedgerSlot", false, "KEYW_RPCMETHOD_MINIMUMLEDGERSLOT" },
    { "requestAirdrop", false, "KEYW_RPCMETHOD_REQUESTAIRDROP" },
    { "sendTransaction", false, "KEYW_RPCMETHOD_SENDTRANSACTION" },
    { "simulateTransaction", false, "KEYW_RPCMETHOD_SIMULATETRANSACTION" },

    { NULL, false, NULL }
  };
  FILE* fd = fopen("keywords.h", "w");
  fprintf(fd, "// This file is generated by genkeywords.cxx. DO NOT EDIT DIRECTLY!\n");
  genmacros(json_table, "fd_webserver_json_keyword", "KEYW_UNKNOWN", fd);
  fclose(fd);
  
  fd = fopen("keywords.c", "w");
  fprintf(fd, "// This file is generated by genkeywords.cxx. DO NOT EDIT DIRECTLY!\n");
  fprintf(fd, "#include \"keywords.h\"\n");
  genmatcher(json_table, "fd_webserver_json_keyword", "KEYW_UNKNOWN", fd);
  fclose(fd);
  
  fd = fopen("test_keywords.h", "w");
  gentest(json_table, "fd_webserver_json_keyword", "KEYW_UNKNOWN", fd);
  fclose(fd);
  
  return 0;
}
