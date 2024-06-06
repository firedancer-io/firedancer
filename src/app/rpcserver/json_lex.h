/*****
      Header file for a json lexical scanner
*****/

#include "../../util/fd_util.h"

// Lexical token value
#define JSON_TOKEN_LBRACKET 1 /* [ */
#define JSON_TOKEN_RBRACKET 2 /* ] */
#define JSON_TOKEN_LBRACE   3 /* { */
#define JSON_TOKEN_RBRACE   4 /* } */
#define JSON_TOKEN_COLON    5 /* : */
#define JSON_TOKEN_COMMA    6 /* , */
#define JSON_TOKEN_NULL     7 /* null */
#define JSON_TOKEN_BOOL     8 /* true or false */
#define JSON_TOKEN_INTEGER  9
#define JSON_TOKEN_FLOAT    10
#define JSON_TOKEN_STRING   11

#define JSON_TOKEN_END      0 /* end of input */
#define JSON_TOKEN_ERROR    -1

// Lexical state
struct json_lex_state {
    // Input json text
    const char* json;
    ulong json_sz;

    // Current position in text
    ulong pos;
    // Last token parsed
    long last_tok;

    // Value of last boolean
    int last_bool;
    // Value of last string, number (as text), or error message. UTF-8 encoded.
    char* last_str;
    ulong last_str_sz;
    ulong last_str_alloc;
    char  last_str_firstbuf[512];
};
typedef struct json_lex_state json_lex_state_t;

// Initialize a lexical state given some json text
void json_lex_state_new(json_lex_state_t* state,
                        const char* json,
                        ulong json_sz);

void json_lex_state_delete(json_lex_state_t* state);

// Retrieve the next token
long json_lex_next_token(json_lex_state_t* state);

// Get the last lexical text result. This can be a string, number (as
// text), or error message.
const char* json_lex_get_text(json_lex_state_t* state, ulong* sz);

// Convert the string to an integer (assuming decimal representation)
long json_lex_as_int(json_lex_state_t* lex);

// Convert the string to a float
double json_lex_as_float(json_lex_state_t* lex);

// Replaces the string with the result of a formatted printf.
void json_lex_sprintf(json_lex_state_t* lex, const char* format, ...)
  __attribute__ ((format (printf, 2, 3)));
