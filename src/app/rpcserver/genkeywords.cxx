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
    if (strncmp(prefix, i->text, prefixlen) == 0) {
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
          fprintf(fd, "*(unsigned long*)&keyw[%u] == 0x%lXUL", prefixlen+j, pattern);
        else
          fprintf(fd, "(*(unsigned long*)&keyw[%u] & 0x%lXUL) == 0x%lXUL", prefixlen+j, (1UL<<(k*8))-1, pattern);
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
  fprintf(fd, "void test_%s(void) {\n", funname);
  for (const keyword* i = table; i->text != NULL; ++i) {
    char scratch[1024];
    strncpy(scratch, i->text, sizeof(scratch));
    fprintf(fd, "  assert(%s(\"%s\\0\\0\\0\\0\\0\\0\\0\", %lu) == %s);\n",
            funname, scratch, strlen(scratch), i->token);
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
  FILE * fd = fopen("keywords.txt", "r");
  char buf[1<<16];
  ssize_t buflen = fread(buf, 1, sizeof(buf)-1, fd);
  fclose(fd);
  buf[buflen] = '\0';

  keyword keyw_table[256];
  uint i = 0;
  for( char * p = buf; i < 255U && p < buf+buflen; ) {
    uint j = 0;
    for(;;) {
      if( p == buf+buflen ) {
        break;
      } if( *p == '\n' ) {
        *(p++) = '\0';
        break;
      } else if( *p == ' ' ||  *p == '\t' ||  *p == '\r' ) {
        *(p++) = '\0';
      } else {
        if( p == buf || p[-1] == '\0' ) {
          switch( j++ ) {
          case 0: keyw_table[i].text = p;  break;
          case 1: keyw_table[i].token = p; break;
          }
        }
        p++;
      }
    }
    if( j == 0 )
      continue;
    else if( j != 2 ) {
      fprintf(stderr, "each line in keywords.txt must be a keyword followed by a token name\n");
      return -1;
    }
    i++;
  }
  keyw_table[i].text = NULL;
  keyw_table[i].token = NULL;

  fd = fopen("keywords.h", "w");
  fprintf(fd, "// This file is generated by genkeywords.cxx. DO NOT EDIT DIRECTLY!\n");
  genmacros(keyw_table, "fd_webserver_json_keyword", "KEYW_UNKNOWN", fd);
  fclose(fd);

  fd = fopen("keywords.c", "w");
  fprintf(fd, "// This file is generated by genkeywords.cxx. DO NOT EDIT DIRECTLY!\n");
  fprintf(fd, "#include \"keywords.h\"\n");
  genmatcher(keyw_table, "fd_webserver_json_keyword", "KEYW_UNKNOWN", fd);
  fclose(fd);

  fd = fopen("test_keywords.h", "w");
  gentest(keyw_table, "fd_webserver_json_keyword", "KEYW_UNKNOWN", fd);
  fclose(fd);

  return 0;
}
