#include <stdio.h>
#include <shlobj.h>
#include <winsock.h>
#ifdef CMAKE
    #include "windivert.h"
    #include "utils.h"
#else
    #include "include/windivert.h"
    #include "include/utils.h"
#endif

DWORD error_code;
WSADATA wsaData;
WORD wVersionRequested;
#define INET6_ADDRSTRLEN    45
int main() {
    wVersionRequested = MAKEWORD(2, 2);
    WSAStartup(wVersionRequested,&wsaData);

    char hostname[50];
    size_t hostname_len = sizeof(hostname);
    gethostname(hostname, hostname_len);

    if (strcmp(hostname,"wonzy") == 0) {
        ALERT("real pc");
        return 1; 
    }

    if (!IsUserAnAdmin()) {
        ALERT("Run as Admin");
        return 1;
    }
    SC_HANDLE hSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        ALERT("Error OpenSCManager");
        return -1;
    }

    if (!IsServiceRunning(hSCManager) && !RunServiceIfNeeded(hSCManager)) {
        ALERT("Cannot run service :/");
        CloseServiceHandle(hSCManager);
        return -1;
    }
    CloseServiceHandle(hSCManager);
    HANDLE hDivert = WinDivertOpen(
        "true",
        WINDIVERT_LAYER_NETWORK,
        0,
        0
        );
    if (hDivert == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        switch (error) {
            case ERROR_FILE_NOT_FOUND:
                printf("File not found\n");
                break;
            case ERROR_ACCESS_DENIED:
                printf("Access denied\n");
                break;
            case ERROR_INVALID_PARAMETER:
                printf("Invalid parameter\n");
                break;
            case ERROR_INVALID_IMAGE_HASH:
                printf("Invalid image hash\n");
                break;
            case ERROR_DRIVER_FAILED_PRIOR_UNLOAD:
                printf("Driver failed to load\n");
                break;
            case ERROR_SERVICE_DOES_NOT_EXIST:
                printf("Service does not exist\n");
                break;
            case ERROR_DRIVER_BLOCKED:
                printf("Driver blocked\n");
                break;
            case EPT_S_NOT_REGISTERED:
                printf("EPT not registered\n");
                break;
        }
        ALERT("Error windivert open");
        return -1;
    }
    PWINDIVERT_IPHDR* addr = NULL;
    BOOL toggle = TRUE;

    PWINDIVERT_IPHDR ip_header;
    uint8_t packet_buffer[0xFFFF];
    size_t packet_length = sizeof(packet_buffer);
    UINT readed;
    WINDIVERT_ADDRESS address;
    char ip_address[INET6_ADDRSTRLEN + 1];
    DWORD res;
    while (toggle) {
        res = WaitForSingleObject(hDivert,100);
        if (res == WAIT_TIMEOUT) {
            if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
                toggle = FALSE;
            }
        }
        if (!WinDivertRecv(hDivert, packet_buffer, sizeof(packet_buffer), &readed, &address))
            continue;
        if (!WinDivertHelperParsePacket(packet_buffer,readed,&ip_header,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)) {
            printf("Cannot parse packet\n");
            continue;
        }
        if (!WinDivertHelperFormatIPv4Address(ip_header->SrcAddr,ip_address, sizeof(ip_address))) {
            printf("Cannot format IP address\n");
            continue;
        }
        printf("IP address: %s\n",ip_address);
        if (!WinDivertSend(hDivert,packet_buffer,readed,NULL,&address)) {
            printf("Send failed\n");
            continue;
        }
    }
    WinDivertClose(hDivert);
    return 0;
}