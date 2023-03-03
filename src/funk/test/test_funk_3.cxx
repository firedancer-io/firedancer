#include "../../util/fd_util.h"
extern "C" {
#include "../fd_funk.h"
}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

static const char* BACKFILE = "/tmp/funktest";

void grinder(int argc, char** argv, bool firsttime) {
  fd_boot( &argc, &argv );

  fd_wksp_t* wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 1UL, fd_log_cpu_id(), "wksp", 0UL );

  ulong index_max = 1000;    // Maximum size (count) of master index
  ulong xactions_max = 100;  // Maximum size (count) of transaction index
  ulong cache_max = 100;     // Maximum number of cache entries
  auto* funk = fd_funk_new(BACKFILE, wksp, 1, index_max, xactions_max, cache_max);

  fd_funk_validate(funk);

  fd_funk_recordid_t recordkeys[16];
  for (int i = 0; i < 16; ++i)
    memset(recordkeys + i, 'a'+i, sizeof(fd_funk_recordid_t));

  union {
      fd_funk_xactionid_t xid;
      struct {
          struct timeval tv;
          ulong counter;
      } s;
  } xid;
  memset(&xid, 0, sizeof(xid));
  gettimeofday(&xid.s.tv, NULL);

  static const ulong RECORDSIZE = 1<<14;
  ulong recorddata[RECORDSIZE/sizeof(ulong)];

  if (!firsttime) {
    for (ulong group = 0; group < 16; group += 4) {
      const void* data;
      if (fd_funk_read(funk, fd_funk_root(funk), recordkeys + group, &data, 0, RECORDSIZE) != (long)RECORDSIZE)
        FD_LOG_ERR(("failed read"));
      for (ulong i = 1; i < 4; ++i) {
        const void* data2;
        if (fd_funk_read(funk, fd_funk_root(funk), recordkeys + group, &data2, 0, RECORDSIZE) != (long)RECORDSIZE)
          FD_LOG_ERR(("failed read"));
        if (memcmp(data, data2, RECORDSIZE) != 0)
          FD_LOG_ERR(("inconsistant data within a transaction"));
      }
    }
  }

  ulong group = 0;
  ulong written = 0;
  ulong lastlog = 0;
  for (;;) {
    
    ulong counter = ++(xid.s.counter);
    for (ulong i = 0; i < RECORDSIZE/sizeof(ulong); ++i)
      recorddata[i] = counter;
    fd_funk_fork(funk, fd_funk_root(funk), &xid.xid);
    for (ulong i = 0; i < 4; ++i) {
      fd_funk_write(funk, &xid.xid, recordkeys + (group+i), recorddata, 0, RECORDSIZE);
      written += RECORDSIZE;
    }
    fd_funk_commit(funk, &xid.xid);

    if (written>>30 != lastlog>>30) {
      FD_LOG_WARNING(("wrote %lu bytes", written));
      lastlog = written;
    }

    group = (group+4)%16;
  }
}

int main(int argc, char** argv) {
  if (argc == 2) {
    // Child process
    if (strcmp(argv[1], "-1") == 0)
      grinder(argc, argv, true);
    else if (strcmp(argv[1], "-2") == 0)
      grinder(argc, argv, false);
    return 0;
  }

  if (argc == 1) {
    // Parent process
    unlink(BACKFILE);
    bool firsttime = true;
    for (;;) {
      pid_t p;
      if ((p = fork()) == 0) {
        static const char* EXE = "build/test/bin/test_funk_3";
        int r = execlp(EXE, EXE, (firsttime ? "-1" : "-2"), NULL);
        if (r == -1)
          fprintf(stderr, "failed to exec %s: %s\n", EXE, strerror(errno));
        return 1;
      }
      firsttime = false;

      sleep(3);

      kill(p, SIGKILL);
      int wstatus;
      waitpid(p, &wstatus, 0);
    }
  }

  return 0;
}
