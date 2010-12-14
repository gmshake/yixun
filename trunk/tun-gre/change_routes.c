#include <unistd.h> //execl() 
#include <string.h> // snprintf()
#include <stdio.h> // FILE fopen() fclose()
#include <netinet/in.h> // in_addr_t sockaddr_in INADDR_ANY
#include <arpa/inet.h> // inet_addr() inet_ntoa
#include <sys/wait.h> // wait()

#include "common_macro.h"
#include "common_logs.h"

/*
 * add sip route entry
 */
int route_add(in_addr_t sip, size_t bits, in_addr_t gateway, const char *iface, const char *flag)
{
    pid_t childpid;
    if ((childpid = fork()) < 0)
    {
        log_perror("[route_add] fork");
        return -1;
    }
    else if (childpid == 0) /* child code */
    {
        if (setuid(geteuid()) < 0)
        {
            log_perror("[route_add] Error setuid %u", geteuid());
            return -1;
        }
        
        char * argv[7];
        int i = 0;
        argv[i++] = "route";
        argv[i++] = "add";

        char buff[64];
        if (bits > 0)
            snprintf(buff, sizeof(buff), "%s/%lu", inet_itoa(sip), bits > 32 ? 32 : bits);
        else
            snprintf(buff, sizeof(buff), "%s", inet_itoa(sip));
        
        argv[i++] = buff;
        
        if (iface != NULL)
        {
            argv[i++] = "-iface";
            argv[i++] = (char *)iface;
        }
        //    execl("/sbin/route", "route", "add", buff, "-iface", iface, NULL);
        else
            argv[i++] = inet_itoa(gateway);
       //     execl("/sbin/route", "route", "add", buff, inet_itoa(gateway), NULL);
            
        if (flag != NULL)
        {
            argv[i++] = (char *)flag;
        }
        argv[i++] = NULL;
        
        execvp("route", argv);
        
        log_perror("[route_add] Child failed to exec \"route\"");
        return -1;
    }
    else if (wait(NULL) != childpid)
    {                  /* parent code */
        log_perror("[route_add] Parent failed to wait due to signal or error");
        return -1;
    }

    return 0;
}

/*
 * change sip route entry
 */
int route_change(in_addr_t sip, size_t bits, in_addr_t gateway, const char *iface)
{
    pid_t childpid;
    if ((childpid = fork()) < 0)
    {
        log_perror("[route_change] fork");
        return -1;
    }
    else if (childpid == 0) /* child code */
    {
        if (setuid(geteuid()) < 0)
        {
            log_perror("[route_change] Error setuid %u", geteuid());
            return -1;
        }
        
        char * argv[7];
        int i = 0;
        argv[i++] = "route";
        argv[i++] = "change";
        
        char buff[64];
        if (bits > 0)
            snprintf(buff, sizeof(buff), "%s/%lu", inet_itoa(sip), bits > 32 ? 32 : bits);
        else
            snprintf(buff, sizeof(buff), inet_itoa(sip));
            
        argv[i++] = buff;
        if (iface != NULL)
        {
            argv[i++] = "-iface";
            argv[i++] = (char *)iface;
        }
        
        argv[i++] = NULL;
        
        /*
        if (iface != NULL)
            execl("/sbin/route", "route", "change", buff, "-iface", iface, NULL);
        else
            execl("/sbin/route", "route", "change", buff, inet_itoa(gateway), NULL);
        */
        
        execvp("route", argv);
        
        log_perror("[route_change] Child failed to exec \"route\"");
        return -1;
    }
    else if (wait(NULL) != childpid)
    {                  /* parent code */
        log_perror("[route_change] Parent failed to wait due to signal or error");
        return -1;
    }
    return 0;
}

/*
 * delete sip route entry
 */
int route_delete(in_addr_t sip, size_t bits)
{
    pid_t childpid;
    if ((childpid = fork()) < 0)
    {
        log_perror("[route_delete] fork");
        return -1;
    }
    else if (childpid == 0) /* child code */
    {
        if (setuid(geteuid()) < 0)
        {
            log_perror("[route_delete] Error setuid %u", geteuid());
            return -1;
        }
        
        char buff[64];
        if (bits > 0)
        {
            if (bits > 32) bits = 32;
            unsigned ui = ntohl(sip);
            ui &=  ~((1 << (32 - bits)) - 1);
            ui = htonl(ui);
            snprintf(buff, sizeof(buff), "%s/%lu", inet_itoa(ui), bits);
        }
        else
            snprintf(buff, sizeof(buff), inet_itoa(sip));
            
        execlp("route", "route", "delete", buff, NULL);
        log_perror("[route_delete] Child failed to exec \"route\"");
        return -1;
    }
    else if (wait(NULL) != childpid)
    {                  /* parent code */
        log_perror("[route_delete] Parent failed to wait due to signal or error");
        return -1;
    }
    return 0;
}

/*
 * get route to sip
 */
in_addr_t route_get(in_addr_t sip, size_t bits)
{
    #define GATEWAY "gateway"
    char buff[256];
    char cmd[64];
    
    if (bits > 0)
        snprintf(cmd, sizeof(cmd), "/sbin/route -n get %s/%lu", inet_itoa(sip), bits > 32 ? 32 : bits);
    else
        snprintf(cmd, sizeof(cmd), "/sbin/route -n get %s", inet_itoa(sip));
    
    FILE *fp = popen(cmd, "r");
    if(!fp){
        log_perror("[route_get] popen \"/sbin/route\"");    
        return 0;
    }
    
    in_addr_t rval = 0;
    do
    {
        fgets(buff, sizeof(buff), fp);
        char *p = strcasestr(buff, GATEWAY);
        if (p)
        {
            rval = inet_addr(p + strlen(GATEWAY) + 2);//found
            break;
        }
    }while(!feof(fp)); // not found
    
    pclose(fp);
    
    return rval;
    #undef GATEWAY
}

/*
 * check if route table have route entry sip
 * on success and true, return -1, otherwise return 0
 */
int route_exist(in_addr_t sip, size_t bits)
{
    char buff[256];
    char cmd[64];
    if (bits > 0)
        snprintf(cmd, sizeof(cmd), "/sbin/route -n get %s/%lu", inet_itoa(sip), bits > 32 ? 32 : bits);
    else
        snprintf(cmd, sizeof(cmd), "/sbin/route -n get %s", inet_itoa(sip));
        
    FILE *fp = popen(cmd, "r");
    if(!fp){
        log_perror("[route_exist] popen \"/sbin/route\"");
        return 0;
    }
    
    int rval = 0;
    do
    {
        fgets(buff, sizeof(buff), fp);
        char *p = strcasestr(buff, "gateway");
        if (p) {
            rval = -1; //found
            break;
        }
    }while(!feof(fp));
    
    pclose(fp);

    return rval;
}

