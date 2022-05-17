#include <signal.h>

#include "proc.h"

#define READ   0
#define WRITE  1
FILE * popen2(const char* command, const char* type, int* pid)
{
    pid_t child_pid;
    int fd[2];
    pipe(fd);

    if((child_pid = fork()) == -1)
    {
        perror("fork");
        exit(1);
    }

    /* child process */
    if (child_pid == 0)
    {
        if (strncmp("r", type, 1) == 0)
        {
            close(fd[READ]);    //Close the READ end of the pipe since the child's fd is write-only
            dup2(fd[WRITE], 1); //Redirect stdout to pipe
        }
        else
        {
            close(fd[WRITE]);    //Close the WRITE end of the pipe since the child's fd is read-only
            dup2(fd[READ], 0);   //Redirect stdin to pipe
        }

        setpgid(child_pid, child_pid); //Needed so negative PIDs can kill children of /bin/sh
        execl("/bin/sh", "/bin/sh", "-c", command, NULL);
        exit(0);
    }
    else
    {
        if (strncmp("r", type, 1) == 0)
        {
            close(fd[WRITE]); //Close the WRITE end of the pipe since parent's fd is read-only
        }
        else
        {
            close(fd[READ]); //Close the READ end of the pipe since parent's fd is write-only
        }
    }

    *pid = child_pid;

    if (strncmp("r", type, 1) == 0)
    {
        return fdopen(fd[READ], "r");
    }

    return fdopen(fd[WRITE], "w");
}

int pclose2(FILE * fp, pid_t pid)
{
    int stat;

    fclose(fp);
    
    pid = -1 * pid;

    kill(pid, SIGKILL);
    while (waitpid(pid, &stat, 0) == -1)
    {
        kill(pid, SIGKILL);
        if (errno != EINTR)
        {
            stat = -1;
            break;
        }
    }

    return stat;
}
