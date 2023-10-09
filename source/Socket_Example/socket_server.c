#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

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

void createSocketCommunication(protocal eProtoType,IPAddrType eIpType, int iPortNumber)
{
    struct sockaddr_in6 serverAddr6, clientAddr6;
    struct sockaddr_in serverAddr, clientAddr;

    int serverSocket = 0, clientSocket = 0;
    socklen_t client_len = sizeof(clientAddr);
    socklen_t client6_len = sizeof(clientAddr6);
 
    memset(&serverAddr6, 0, sizeof(serverAddr6));
    memset(&serverAddr, 0, sizeof(serverAddr));
    memset(&clientAddr6, 0, sizeof(clientAddr6));
    memset(&clientAddr, 0, sizeof(clientAddr));

    if (IPv6 == eIpType)
    {
        if (TCP == eProtoType)
        {
            serverSocket = socket(AF_INET6, SOCK_STREAM, 0);
        }
        else if (UDP == eProtoType)
        {
            serverSocket = socket(AF_INET6, SOCK_DGRAM, 0);
        }
        else
        {
            return;
        }
        serverAddr6.sin6_family = AF_INET6;
        serverAddr6.sin6_port = htons(iPortNumber);
        serverAddr6.sin6_addr = in6addr_any;
    }
    else if (IPv4 == eIpType)
    {
        if (TCP == eProtoType)
        {
            serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        }
        else if (UDP == eProtoType)
        {
            serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
        }
        else
        {
            return;
        }
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(iPortNumber);
        serverAddr.sin_addr.s_addr = INADDR_ANY;
    }
    else
        return;

    if (-1 == serverSocket)
    {
        printf("Socket creation failed\n");
        return ;
    }

    int iBindRet = 0;
    if (IPv4 == eIpType)
    {
        iBindRet = bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    }
    else if (IPv6 == eIpType)
    {
        iBindRet = bind(serverSocket, (struct sockaddr*)&serverAddr6, sizeof(serverAddr6));
    }
    else
        return;

    if (-1 == iBindRet)
    {
        printf ("Binding failed\n");
        return;
    }
    printf ("Binding is successfull\n");
    if (TCP == eProtoType)
    {
        if ( -1 == (listen(serverSocket, 5)))
        {
            printf ("Failed to listen on socket\n");
            return;
        }
        printf ("Listening is successfull\n");

        if (IPv4 == eIpType)
        {
            clientSocket = (accept(serverSocket, (struct sockaddr*)&clientAddr, &client_len));
        }
        else if (IPv6 == eIpType)
        {
            clientSocket = (accept(serverSocket, (struct sockaddr*)&clientAddr6, &client6_len));
        }
        else
            return;
        if ( -1 == clientSocket)
        {
            printf ("Failed to accept the client connection\n");
        }
        printf ("Client connected\n");
    }

    char aBuf[1024];
    ssize_t bytesReceived;

    while (1)
    {
        memset(aBuf, 0, sizeof(aBuf));
        if(TCP == eProtoType)
        {
            bytesReceived = recv(clientSocket, aBuf, sizeof(aBuf), 0);
        }
        else if (UDP == eProtoType)
        {
            if (IPv6 == eIpType)
            {
                bytesReceived = recvfrom (serverSocket, aBuf, sizeof(aBuf), 0, (struct sockaddr*)&clientAddr6, &client6_len);
            }
            else if (IPv4 == eIpType)
            {
                bytesReceived = recvfrom (serverSocket, aBuf, sizeof(aBuf), 0, (struct sockaddr*)&clientAddr, &client_len);
            }
            else
                break;
        }
        else
            break;

        if (0 >= bytesReceived)
	    break;
        aBuf[bytesReceived] = '\0';
        printf ("Received : %s", aBuf);

        if(TCP == eProtoType)
        {
            send (clientSocket, aBuf, strlen(aBuf), 0);
        }
        else if (UDP == eProtoType)
        {
            if (IPv6 == eIpType)
            {
                sendto(serverSocket, aBuf, strlen(aBuf), 0, (struct sockaddr*)&clientAddr6, client6_len);
            }
            else if (IPv4 == eIpType)
            {
                sendto(serverSocket, aBuf, strlen(aBuf), 0, (struct sockaddr*)&clientAddr, client_len);
            }
        }
	if (strstr(aBuf, ":End"))
        {
            break;
        }
    }

    if (TCP == eProtoType)
    {
        close(clientSocket);
    }
    close(serverSocket);
}

int main (void)
{
    int iChoice = 0;
    int iPortNumber = 0;
    int iIPv4orIPv6 = 0;
    while(1)
    {
        printHelp();
        printf ("Enter the choice: ");
        scanf (" %d", &iChoice);

        switch(iChoice)
        {
            case 1:
            {
                printIpv6orIpv4();
                scanf ("%d", &iIPv4orIPv6);
                switch(iIPv4orIPv6)
                {
                    case 1:
                    {
                        printf ("Enter the port number: ");
                        scanf ("%d", &iPortNumber);
                        createSocketCommunication(TCP, IPv4, iPortNumber);
                        break;
                    }
                    case 2:
                    {
                        printf ("Enter the port number: ");
                        scanf ("%d", &iPortNumber);
                        createSocketCommunication(TCP, IPv6, iPortNumber);
                        break;
                    }
                    default:
                    {
                        printf ("Invalid choice for port number\n");
                        break;
                    }
                }
                break;
            }
            case 2:
            {
                printIpv6orIpv4();
                scanf ("%d", &iIPv4orIPv6);
                switch(iIPv4orIPv6)
                {
                    case 1:
                    {
                        printf ("Enter the port number: ");
                        scanf ("%d", &iPortNumber);
                        createSocketCommunication(UDP, IPv4, iPortNumber);
                        break;
                    }
                    case 2:
                    {
                        printf ("Enter the port number: ");
                        scanf ("%d", &iPortNumber);
                        createSocketCommunication(UDP, IPv6, iPortNumber);
                        break;
                    }
                    default:
                    {
                        printf ("Invalid choice for port number\n");
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
                printf("Invalid choice protocal\n");
                break;
            }
        }
    }
}
