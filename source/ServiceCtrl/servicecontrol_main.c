#include "servicecontrol_apis.h"
#include "servicecontrol_rbus_handler_apis.h"
#include "servicecontrol_log.h"

static void daemonize(void)
{
    switch (fork())
    {
        case 0:
            break;
        case -1:
            // Error
            SvcCtrlError(("Error daemonizing (fork)! %d - %s\n", errno, strerror(errno)));
            exit(0);
            break;
        default:
            _exit(0);
    }

    if (setsid() < 0)
    {
        SvcCtrlError(("Error demonizing (setsid)! %d - %s\n", errno, strerror(errno)));
        exit(0);
    }

#ifndef  _DEBUG
    int fd;
    fd = open("/dev/null", O_RDONLY);
    if (fd != 0)
    {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1)
    {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2)
    {
        dup2(fd, 2);
        close(fd);
    }
#endif
}

void sig_handler(int sig)
{
    if ( sig == SIGINT )
    {
        signal(SIGINT, sig_handler); /* reset it to this function */
        SvcCtrlInfo(("SIGINT received!\n"));
        ServiceControl_Deinit();
        ServiceControl_Log_Deinit();
        exit(0);
    }
    else if ( sig == SIGUSR1 )
    {
        signal(SIGUSR1, sig_handler); /* reset it to this function */
        SvcCtrlInfo(("SIGUSR1 received!\n"));
    }
    else if ( sig == SIGUSR2 )
    {
        SvcCtrlInfo(("SIGUSR2 received!\n"));
    }
    else if ( sig == SIGCHLD )
    {
        signal(SIGCHLD, sig_handler); /* reset it to this function */
        SvcCtrlInfo(("SIGCHLD received!\n"));
    }
    else if ( sig == SIGPIPE )
    {
        signal(SIGPIPE, sig_handler); /* reset it to this function */
        SvcCtrlInfo(("SIGPIPE received!\n"));
    }
    else
    {
        SvcCtrlInfo(("Signal %d received, exiting!\n", sig));
        ServiceControl_Deinit();
        ServiceControl_Log_Deinit();
        exit(0);
    }
}

int main()
{
    daemonize();

    ServiceControl_Log_Init();
    ServiceControl_Init();
    ServiceControl_Rbus_Init();
    spawn_svc_restart_queue_loop();

    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);
    signal(SIGSEGV, sig_handler);
    signal(SIGBUS, sig_handler);
    signal(SIGKILL, sig_handler);
    signal(SIGFPE, sig_handler);
    signal(SIGILL, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGHUP, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    while(1)
    {
        sleep(30);
    }
    return 0;
}

