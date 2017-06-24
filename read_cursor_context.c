#include <sys/ptrace.h>
#include <sys/wait.h>
#include <asm/prctl.h>
#include <asm/ptrace.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ptrace_attach(int pid) {
  int ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  if (ret == -1) {
    printf("Failed to ptrace attach to PID %d: %s\n", pid, strerror(errno));
    exit(3);
  }
  // ptrace attach sends SIGSTOP to the process and we have to wait for it to be
  // delivered, otherwise we 1) first time don't really attach 2) leave spurious
  // SIGSTOP sent, stopping the server process.
  int status = 0;
  pid_t wpidret = waitpid(-1, &status, __WALL);
  if (wpidret < 0) {
    printf("Failed to wait for SIGSTOP to be delivered to PID %d: %s\n", pid,
           strerror(errno));
  }
}
void ptrace_detach(int pid) {
  int ret = ptrace(PTRACE_DETACH, pid, NULL, NULL);
  if (ret == -1) {
    printf("Failed to ptrace detach from PID %d: %s\n", pid, strerror(errno));
    exit(3);
  }
}

uint64_t ptrace_addr(int pid, uint64_t addr) {
  uint64_t ret = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
  // we should check errno, but let's just hope it works
  return ret;
}

uint64_t getThreadAreaTbss(int pid) {
  uint64_t thread_area_base;
  int ret = ptrace(PTRACE_ARCH_PRCTL, pid, &thread_area_base, ARCH_GET_FS);
  if (ret == -1) {
    printf("Failed to ptrace get FS from PID %d: %s\n", pid, strerror(errno));
    exit(3);
  }
  uint64_t thread_area_base_8 = ptrace_addr(pid, thread_area_base + 0x8);
  uint64_t thread_area_base_8_10 = ptrace_addr(pid, thread_area_base_8 + 0x10);
  return thread_area_base_8_10;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage:\n\
./read_cursor_context PID symbol_address\n\
Works for 12c only (11g is simpler, you don't need handle thread-local variables, see source code).\n\
And only when there is really just one thread, as we can't specify which thread to access.\n\
\n\
PID: process ID of the server process\n\
symbol_address: address of kxscio symbol, as obtained by:\n\
readelf -s $ORACLE_HOME/bin/oracle | grep kxscio_$ | sed 's/^.*: *\\([0-9a-f]\\+\\) *[0-9]\\+ *\\([A-Z]\\+\\).*$/0x\\1 \\2/' | head -1\n\
(you should see \"TLS\" in the output - indicating this is a 12c threaded executable).\n");
    return 0;
  }

  int pid = atoi(argv[1]);

  uint64_t symbol_address;
  sscanf(argv[2], "%li", &symbol_address);

  ptrace_attach(pid);

  /* tbss is thread-local version of bss = static data in an ELF executable.
   * For 11g (which is not threaded), just put 0 here.
   * Getting TBSS base is not any Oracle-spcific magic, it should be the same
   * for any Linux binary with thread-local storage.*/
  uint64_t tbss = getThreadAreaTbss(pid);

  // This is the address of kxscio in memory.
  uint64_t a_kxscio = symbol_address + tbss;

  uint64_t kxscio = ptrace_addr(pid, a_kxscio);

  // and cursor context is in this magic position in kxscio structure.
  uint64_t cursorContext = ptrace_addr(pid, kxscio + 0x68);

  printf("cursorContext = 0x%08lx\n", cursorContext);

  ptrace_detach(pid);
}
