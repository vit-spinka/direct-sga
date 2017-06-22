#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>

void attach_SGA(int pid) {
  char proc_maps[100];
  sprintf(proc_maps, "/proc/%d/maps", pid);
  FILE *proc_maps_FILE = fopen(proc_maps, "rt");
  if (!proc_maps_FILE) {
    printf("Failed to read proc map for PID %d: %s\n", pid, strerror(errno));
    exit(1);
  }

  char line[1024];
  uint64_t startAddress;
  uint64_t endAddress;
  int shmid;
  int cnt = 0;

  while (fgets(line, sizeof(line) - 1, proc_maps_FILE)) {
    if (!strstr(line, "/SYSV")) {
      continue;
    }
    //    printf("|%s\n", line);
    char a[100];
    char b[100];
    char c[100];
    uint64_t prev_startAddress = startAddress;
    sscanf(line, "%lx-%lx %s %s %s %d\n", &startAddress, &endAddress, a, b, c,
           &shmid);
    cnt++;
    /* The first two lines refer to the same shmid and we have to join them. */
    if (cnt == 1) {
      continue;
    }
    if (cnt == 2) {
      startAddress = prev_startAddress;
    }
    // printf("Attaching SGA segment, range 0x%lx - 0x%lx, shmid %d\n",
    // startAddress, endAddress, shmid);
    void *map = shmat(shmid, (void *)startAddress, SHM_RDONLY);
    if (map == (void *)-1) {
      printf(
          "Failed to attach SGA segment: range 0x%lx - 0x%lx, shmid %d: %s\n",
          startAddress, endAddress, shmid, strerror(errno));
      exit(1);
    }
  }

  fclose(proc_maps_FILE);
}

int main(int argc, char **argv) {
  if (argc != 4) {
    printf("Usage:\n\
./read_SGA_bytes PID address length\n\
\n\
PID: process ID of any Oracle process of this instance. (We use it just to read /proc/PID/ to get SGA map.)\n\
address: starting address of the dump. It\'s legal to specify it in decimal or hex (1234 or 0xab123). Octal is also supported (0123).\n\
length: number of bytes to dump\n\
\n\
!! The output is binary !!\n\
This is intentional, so you can use `xxd` or `od` to format it per your requirements.\n");
    return 0;
  }

  int pid = atoi(argv[1]);
  attach_SGA(pid);

  uint64_t address;
  sscanf(argv[2], "%li", &address);

  int length;
  sscanf(argv[3], "%i", &length);

  uint64_t a;
  for (a = address; a < address + length; a++) {
    // printf("0x%lx: 0x%02x\n", a, *((uint8_t*)a));
    putchar(*((uint8_t *)a));
  }
}
