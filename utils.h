//
// Created by alper on 31.10.2025.
//
#pragma once

#include <windows.h>
#include <stdlib.h>
#include <string.h>

#define ALERT(msg)(MessageBoxW(NULL,L##msg,L"Error",MB_OK|MB_ICONERROR));

typedef struct tagWIN32SERVICES {
    DWORD serviceCount;
    LPENUM_SERVICE_STATUSW serviceStatus;
} *Win32Services;

DWORD GetBufferServiceStatusSize(SC_HANDLE hService) {
    if (!hService) {
        ALERT("Error SC_HANDLE is invalid :/");
        return 0;
    }
    DWORD buffersize = 0;
    DWORD servicecount = 0;
    EnumServicesStatusW(
        hService,
        SERVICE_KERNEL_DRIVER,
        SERVICE_ACTIVE,
        NULL,
        0,
        &buffersize,
        &servicecount,
        NULL
    );
    return buffersize;
}

Win32Services GetWin32Services(SC_HANDLE hService,DWORD serviceStatusType) {
    if (!hService) {
        ALERT("Error SC_HANDLE is invalid :/");
        return NULL;
    }
    Win32Services serviceStatus = (Win32Services)malloc(sizeof(struct tagWIN32SERVICES));
    if (!serviceStatus) {
        ALERT("Memory allocation error");
        return NULL;
    }
    DWORD buffersize = GetBufferServiceStatusSize(hService);
    if (!buffersize || buffersize == 0) {
        ALERT("GetBufferServiceStatus failed");
        free(serviceStatus);
        return NULL;
    }
    DWORD buffsize = 0;
    serviceStatus->serviceStatus = (LPENUM_SERVICE_STATUSW)malloc(buffersize);
    if (!serviceStatus->serviceStatus) {
        ALERT("Memory allocation error");
        free(serviceStatus);
        return NULL;
    }
    BOOL result = EnumServicesStatusW(
        hService,
        SERVICE_KERNEL_DRIVER,
        serviceStatusType,
        serviceStatus->serviceStatus,
        buffersize,
        &buffsize,
        &serviceStatus->serviceCount,NULL);
    if (!result) {
        ALERT("EnumServicesStatusW failed");
        free(serviceStatus->serviceStatus);
        free(serviceStatus);
        return NULL;
    }
    return serviceStatus;
}

void DestroyWin32Services(Win32Services serviceStatus) {
    if (!serviceStatus) {
        ALERT("Error SC_HANDLE is invalid :/");
        return;
    }
    free(serviceStatus->serviceStatus);
    free(serviceStatus);
}

BOOL IsServiceRunning(SC_HANDLE hService) {
    if (!hService) {
        ALERT("Error SC_HANDLE is invalid :/");
        return FALSE;
    }
    Win32Services serviceStatus = GetWin32Services(hService,SERVICE_ACTIVE);
    if (!serviceStatus) {
        ALERT("GetWin32Services failed");
        return FALSE;
    }
    for (DWORD i = 0; i < serviceStatus->serviceCount; i++) {
        if (wcscmp(L"firewall", serviceStatus->serviceStatus[i].lpServiceName) == 0) {
            return TRUE;
        }
    }
    DestroyWin32Services(serviceStatus);
    return FALSE;
}

BOOL RunServiceIfNeeded(SC_HANDLE hService) {
    if (!hService) {
        ALERT("Error SC_HANDLE is invalid :/");
        return FALSE;
    }
    SC_HANDLE serviceHandle = OpenServiceW(hService,L"firewall",SERVICE_ALL_ACCESS);
    if (!serviceHandle) {
        ALERT("OpenServiceW failed");
        return FALSE;
    }
    BOOL result = StartServiceW(serviceHandle,0,NULL);
    CloseServiceHandle(serviceHandle);
    return result;
}