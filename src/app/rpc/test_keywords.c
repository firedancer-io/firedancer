#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include "keywords.h"
#include "test_keywords.h"

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  test_fd_webserver_json_keyword();
  printf("test passed!\n");
  return 0;
}
