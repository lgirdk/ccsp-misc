/* This is a socket client application, you need to copy this socket_client.c file to the client machine, compile and generate
 * the binary and then run the binary on client machine after running the server binary on gateway.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <errno.h>
#include <arpa/inet.h>

typedef enum
{
    TCP,
    UDP
}protocal;

typedef enum
{
    IPv4,
    IPv6
}IPAddrType;

void printHelp(void)
{
    printf("===================\n");
    printf("1. Tcp communication\n");
    printf("2. Udp communication\n");
    printf("3. exit\n");
    printf("===================\n");
}

void printIpv6orIpv4(void)
{
    printf("1. IPv4 socket creation\n");
    printf("2. IPv6 socket creation\n");
    printf ("Enter the choice: ");
}

void createSocketCommunication(protocal eProtoType,IPAddrType eIpType, char * pServerAddress, int iPortNumber)
{
    int clientSocket;
    char aStr[128]= {0};
    struct sockaddr_in6 serverAddr6;
    struct sockaddr_in serverAddr;
    int retConnect = 0;

    if (NULL == pServerAddress)
    {
        printf ("pServerAddress is NULL\n");
        return;
    }

    if (IPv6 == eIpType)
    {
        if(TCP == eProtoType)
        {
            clientSocket = socket (AF_INET6, SOCK_STREAM, 0);
        }
        else if (UDP == eProtoType)
        {
            clientSocket = socket (AF_INET6, SOCK_DGRAM, 0);
        }
        strcpy(aStr, pServerAddress);
        serverAddr6.sin6_family = AF_INET6;
        serverAddr6.sin6_port = htons(iPortNumber);
        inet_pton(AF_INET6, aStr, &serverAddr6.sin6_addr);
    }
    else if (IPv4 == eIpType)
    {
        if(TCP == eProtoType)
            clientSocket = socket (AF_INET, SOCK_STREAM, 0);
        else if (UDP == eProtoType)
            clientSocket = socket (AF_INET, SOCK_DGRAM, 0);

        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(iPortNumber);
        inet_pton(AF_INET, pServerAddress, &serverAddr.sin_addr);
    }
    else
        return;

    if (-1 == clientSocket)
    {
        printf ("failed to create the socket\n");
        return;
    }

    if(TCP == eProtoType)
    {
        if (IPv6 == eIpType)
        {
            retConnect = connect (clientSocket, (struct sockaddr*)&serverAddr6, sizeof(serverAddr6));
        }
        else if (IPv4 == eIpType)
        {
            retConnect = connect (clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        }
        else
            return;

        if (-1 == retConnect)
        {
            printf ("Failed to connect to the server:%d:%s\n", errno, strerror(errno));
            return;
        }
        printf ("Connected to the server\n");
   }
   char aBuf[1024];
   ssize_t bytesRecived;

   while(1)
   {
       fflush(stdin);
       printf ("Enter the message: ");
       fgets (aBuf, sizeof(aBuf), stdin);

       if (TCP == eProtoType)
       {
           send (clientSocket, aBuf, strlen(aBuf), 0);
           bytesRecived = recv(clientSocket, aBuf, sizeof(aBuf),0);
       }
       else if (UDP == eProtoType)
       {
           if(IPv6 == eIpType)
               sendto (clientSocket, aBuf, strlen(aBuf), 0, (struct sockaddr*)&serverAddr6, sizeof(serverAddr6));
           else if (IPv4 == eIpType)
               sendto (clientSocket, aBuf, strlen(aBuf), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
           else
               break;

           bytesRecived= recvfrom(clientSocket, aBuf, sizeof(aBuf), 0, NULL, NULL);
       }

       if (0 >= bytesRecived)
           break;

       aBuf[bytesRecived] = '\0';
       if (strstr(aBuf, ":End"))
       { 
           printf ("Server response:%s\n", aBuf);
           break;
       }
       printf ("Server response:%s\n", aBuf);
       printf ("Type :End to stop connection\n");
   }
   close(clientSocket);
}

int main (int argc, char * argv[])
{
    int iChoice = 0;
    int iPortNumber = 0;
    char aServerAddr[128] = {0};
    while(1)
    {
        printHelp();
        printf ("Enter the choice: ");
        scanf (" %d", &iChoice);

        switch(iChoice)
        {
            case 1:
            {
                int iIPv4orIPv6 = 0;
                printIpv6orIpv4();
                scanf ("%d", &iIPv4orIPv6);
                switch(iIPv4orIPv6)
                {
                    case 1:
                    {
                        fflush(stdin);
                        printf ("Enter the server address: ");
                        fgets (aServerAddr, sizeof(aServerAddr), stdin);
                        aServerAddr[strlen(aServerAddr)-1] = '\0';

                        printf ("Enter the port number: ");
                        scanf ("%d", &iPortNumber);
                        createSocketCommunication(TCP, IPv4, aServerAddr, iPortNumber);
                        break;
                    }
                    case 2:
                    {
                        fflush(stdin);
                        printf ("Enter the server address: ");
                        fgets (aServerAddr, sizeof(aServerAddr), stdin);
                        aServerAddr[strlen(aServerAddr)-1] = '\0';

                        printf ("Enter the port number: ");
                        scanf ("%d", &iPortNumber);
                        createSocketCommunication(TCP, IPv6, aServerAddr, iPortNumber);
                        break;
                    }
                    default:
                    {
                        printf ("Invalid choice\n");
                        break;
                    }
                }
                break;
            }
            case 2:
            {
                int iIPv4orIPv6 = 0;
                printIpv6orIpv4();
                scanf ("%d", &iIPv4orIPv6);
                switch(iIPv4orIPv6)
                {
                    case 1:
                    {
                        fflush(stdin);
                        printf ("Enter the server address: ");
                        fgets (aServerAddr, sizeof(aServerAddr), stdin);
                        aServerAddr[strlen(aServerAddr)-1] = '\0';

                        printf ("Enter the port number: ");
                        scanf ("%d", &iPortNumber);
                        createSocketCommunication(UDP, IPv4, aServerAddr,iPortNumber);
                        break;
                    }
                    case 2:
                    {
                        fflush(stdin);
                        printf ("Enter the server address: ");
                        fgets (aServerAddr, sizeof(aServerAddr), stdin);
                        aServerAddr[strlen(aServerAddr)-1] = '\0';

                        printf ("Enter the port number: ");
                        scanf ("%d", &iPortNumber);
                        createSocketCommunication(UDP, IPv6, aServerAddr,iPortNumber);
                        break;
                    }
                    default:
                    {
                        printf ("Invalid choice\n");
                        break;
                    }
                }
                break;
            }
            case 3:
            {
                exit(0);
            }
            default:
            {
                printf("Invalid choice\n");
                break;
            }
        }
    }
}
