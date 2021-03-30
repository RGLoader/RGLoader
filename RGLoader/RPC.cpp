#include "stdafx.h"
#include "utilities.h"
#include "HvExpansion.h"

#include "RPC.h"

int BufferedSend(SOCKET sock, PBYTE buffer, DWORD size) {
	int bLeft = size;
	int sBytes = 0;
	while (bLeft > 0) {
		int tsBytes = NetDll_send(XNCALLER_SYSAPP, sock, (const char*)(buffer + sBytes), (bLeft >= 2048 ? 2048 : bLeft), 0);
		if (tsBytes == SOCKET_ERROR) {
			continue;
		}
		bLeft -= tsBytes;
		sBytes += tsBytes;
	}
	return sBytes;
}

int BufferedReceive(SOCKET sock, PBYTE buffer, DWORD size) {
	int bLeft = size;
	int rBytes = 0;
	while (bLeft > 0) {
		int trBytes = NetDll_recv(XNCALLER_SYSAPP, sock, (const char*)(buffer + rBytes), (bLeft >= 2048 ? 2048 : bLeft), 0);
		if (trBytes == SOCKET_ERROR) {
			continue;
		}
		bLeft -= trBytes;
		rBytes += trBytes;
	}
	return rBytes;
}

void RPCClientThread(SOCKET sock) {
	BYTE buffer[4] = { 0 };
	int size = NetDll_recv(XNCALLER_SYSAPP, sock, (const char*)&buffer, 4, 0);
	if (size == 4) {  // received packet size
		DWORD pktSize = *(PDWORD)&buffer;
		RPCDebugPrint("RPC", "Receiving packet with size 0x%04X...\n", pktSize);
		PBYTE pktBuf = (PBYTE)malloc(pktSize);
		ZeroMemory(pktBuf, pktSize);

		BufferedReceive(sock, pktBuf, pktSize);

		BYTE pktCmd = *pktBuf;
		PBYTE pktData = pktBuf + 1;
		if (pktCmd == RPCPeekBYTE) {  // peek BYTE
			/* InfoPrint("Shutting down RPC...\n");
			free(pktBuf);
			NetDll_shutdown(XNCALLER_SYSAPP, cliSock, SD_BOTH);
			NetDll_closesocket(XNCALLER_SYSAPP, cliSock);
			goto SvrSockDone; */
			QWORD peekAddr = *(PQWORD)pktData;
			RPCDebugPrint("RPC", "Peeking BYTE @ 0x%llX...\n", peekAddr);
			BYTE v = HvPeekBYTE(peekAddr);
			BufferedSend(sock, (PBYTE)&v, sizeof(BYTE));
		} else if (pktCmd == RPCPeekWORD) {  // peek WORD
			QWORD peekAddr = *(PQWORD)pktData;
			RPCDebugPrint("RPC", "Peeking WORD @ 0x%llX...\n", peekAddr);
			WORD v = HvPeekWORD(peekAddr);
			BufferedSend(sock, (PBYTE)&v, sizeof(WORD));
		} else if (pktCmd == RPCPeekDWORD) {  // peek DWORD
			QWORD peekAddr = *(PQWORD)pktData;
			RPCDebugPrint("RPC", "Peeking DWORD @ 0x%llX...\n", peekAddr);
			DWORD v = HvPeekDWORD(peekAddr);
			BufferedSend(sock, (PBYTE)&v, sizeof(DWORD));
		} else if (pktCmd == RPCPeekQWORD) {  // peek QWORD
			QWORD peekAddr = *(PQWORD)pktData;
			RPCDebugPrint("RPC", "Peeking QWORD @ 0x%llX...\n", peekAddr);
			QWORD v = HvPeekQWORD(peekAddr);
			BufferedSend(sock, (PBYTE)&v, sizeof(QWORD));
		} else if (pktCmd == RPCPeekBytes) {  // peek bytes
			QWORD peekAddr = *(PQWORD)pktData;
			DWORD peekSize = *(PDWORD)(pktData + sizeof(QWORD));
			RPCDebugPrint("RPC", "Peeking 0x%lX bytes(s) @ 0x%llX...\n", peekSize, peekAddr);
			PBYTE peekBuf = (PBYTE)malloc(peekSize);
			memset(peekBuf, 0, peekSize);
			HvPeekBytes(peekAddr, peekBuf, peekSize);

			BufferedSend(sock, (PBYTE)&peekSize, sizeof(DWORD));  // send size
			BufferedSend(sock, peekBuf, peekSize);  // send data

			free(peekBuf);
		} else if (pktCmd == RPCPokeBYTE) {  // poke BYTE
			QWORD pokeAddr = *(PQWORD)pktData;
			BYTE pokeValue = *(PBYTE)(pktData + sizeof(QWORD));
			RPCDebugPrint("RPC", "Poking BYTE 0x%02X @ 0x%llX...\n", pokeValue, pokeAddr);

			BOOL ret = NT_SUCCESS(HvPokeBYTE(pokeAddr, pokeValue));
			BufferedSend(sock, (PBYTE)&ret, sizeof(BOOL));
		} else if(pktCmd == RPCPokeWORD) {  // poke WORD
			QWORD pokeAddr = *(PQWORD)pktData;
			WORD pokeValue = *(PWORD)(pktData + sizeof(QWORD));
			RPCDebugPrint("RPC", "Poking WORD 0x%hX @ 0x%llX...\n", pokeValue, pokeAddr);

			BOOL ret = NT_SUCCESS(HvPokeWORD(pokeAddr, pokeValue));
			BufferedSend(sock, (PBYTE)&ret, sizeof(BOOL));
		} else if (pktCmd == RPCPokeDWORD) {  // poke DWORD
			QWORD pokeAddr = *(PQWORD)pktData;
			DWORD pokeValue = *(PDWORD)(pktData + sizeof(QWORD));
			RPCDebugPrint("RPC", "Poking DWORD 0x%lX @ 0x%llX...\n", pokeValue, pokeAddr);

			BOOL ret = NT_SUCCESS(HvPokeDWORD(pokeAddr, pokeValue));
			BufferedSend(sock, (PBYTE)&ret, sizeof(BOOL));
		} else if (pktCmd == RPCPokeQWORD) {  // poke QWORD
			QWORD pokeAddr = *(PQWORD)pktData;
			QWORD pokeValue = *(PQWORD)(pktData + sizeof(QWORD));
			RPCDebugPrint("RPC", "Poking QWORD 0x%llX @ 0x%llX...\n", pokeValue, pokeAddr);

			BOOL ret = NT_SUCCESS(HvPokeQWORD(pokeAddr, pokeValue));
			BufferedSend(sock, (PBYTE)&ret, sizeof(BOOL));
		} else if(pktCmd == RPCPokeBytes) {  // poke bytes
			QWORD pokeAddr = *(PQWORD)pktData;
			PBYTE pokeData = pktData + sizeof(QWORD);
			DWORD pokeSize = pktSize - sizeof(BYTE) - sizeof(QWORD);
			RPCDebugPrint("RPC", "Poking 0x%lX byte(s) @ 0x%llX...\n", pokeSize, pokeAddr);

			BOOL ret = NT_SUCCESS(HvPokeBytes(pokeAddr, pokeData, pokeSize));
			BufferedSend(sock, (PBYTE)&ret, sizeof(BOOL));
		} else if (pktCmd == RPCGetModuleProcedureAddress) {
			DWORD modOrd = *(PDWORD)(pktData + strlen((char*)pktData) + 1);
			RPCDebugPrint("RPC", "Getting procedure address for ordinal 0x%X in module \"%s\"...\n", modOrd, (char*)pktData);

			HMODULE hMod = GetModuleHandle((char*)pktData);
			DWORD addr;
			BOOL ret = NT_SUCCESS(XexGetProcedureAddress(hMod, modOrd, &addr));
			if(ret == TRUE)
				BufferedSend(sock, (PBYTE)&addr, sizeof(DWORD));
			else
				BufferedSend(sock, (PBYTE)&ret, sizeof(BOOL));
		} else if (pktCmd == RPCPerformCall) {
			QWORD callAddr = *(PQWORD)pktData;

			double FloatArgs[36], f1;
			QWORD TempInt, IntArgs[36];
			ZeroMemory(IntArgs, sizeof(IntArgs));
			ZeroMemory(FloatArgs, sizeof(FloatArgs));

			f1 = ((double(*)(QWORD, ...))callAddr)(
				IntArgs[0], IntArgs[1], IntArgs[2], IntArgs[3],
				IntArgs[4], IntArgs[5], IntArgs[6], IntArgs[7],

				FloatArgs[0], FloatArgs[1], FloatArgs[2], FloatArgs[3],
				FloatArgs[4], FloatArgs[5], FloatArgs[6], FloatArgs[7]
			);
		} else if (pktCmd == RPCListModules) {
			PDM_WALK_MODULES pWalkMod = NULL;
			DMN_MODLOAD modLoad;
			HRESULT hr = DmWalkLoadedModules(&pWalkMod, &modLoad);
			if (hr != XBDM_NOERR)
				RPCDebugPrint("ERROR", "Error walking loaded modules!\n");
			while(hr == XBDM_NOERR) {
				RPCDebugPrint("RPC", "%s\n", modLoad.Name);
				hr = DmWalkLoadedModules(&pWalkMod, &modLoad);
			}
			DmCloseLoadedModules(pWalkMod);
		} else if (pktCmd == RPCReboot) {
			RPCDebugPrint("RPC", "Rebooting now...\n");
			HalReturnToFirmware(HalRebootQuiesceRoutine);
		} else if (pktCmd == RPCShutdown) {
			RPCDebugPrint("RPC", "Shutting down now...\n");
			HalReturnToFirmware(HalPowerDownRoutine);
		}

		free(pktBuf);
		NetDll_shutdown(XNCALLER_SYSAPP, sock, SD_BOTH);
		NetDll_closesocket(XNCALLER_SYSAPP, sock);
	}
}

void RPCServerThread() {
	WSADATA wsaData;
	DWORD sockErr;
	SOCKADDR_IN name;
	name.sin_family = AF_INET;
	name.sin_port = htons(RPCPort);
	name.sin_addr.S_un.S_addr = inet_addr(RPCAddr);
	// XNetStartupParams xnsp;

	// startup networking
	if ((sockErr = NetDll_WSAStartupEx(XNCALLER_SYSAPP, MAKEWORD(2, 2), &wsaData, 2)) != S_OK) {
		RPCDebugPrint("RPC", "NetDll_WSAStartupEx failed!\n");
	}
	// create socket
	SOCKET svrSock = NetDll_socket(XNCALLER_SYSAPP, AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (svrSock == INVALID_SOCKET) {
		RPCDebugPrint("RPC", "NetDll_socket failed!\n");
		WSACleanup();
	}
	// set sock opts
	DWORD soVal = 5000;  // 5000 ms
	NetDll_setsockopt(XNCALLER_SYSAPP, svrSock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&soVal, 4);
	NetDll_setsockopt(XNCALLER_SYSAPP, svrSock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&soVal, 4);
	NetDll_setsockopt(XNCALLER_SYSAPP, svrSock, SOL_SOCKET, SO_SNDBUF, (const char*)&RPCBufferSize, 4);
	NetDll_setsockopt(XNCALLER_SYSAPP, svrSock, SOL_SOCKET, SO_RCVBUF, (const char*)&RPCBufferSize, 4);
	soVal = 1;  // true
	NetDll_setsockopt(XNCALLER_SYSAPP, svrSock, SOL_SOCKET, 0x5801, (const char*)&soVal, 4);
	// bind to the port
	if ((sockErr = NetDll_bind(XNCALLER_SYSAPP, svrSock, (SOCKADDR*)&name, sizeof(name))) != S_OK) {
		RPCDebugPrint("RPC", "NetDll_bind failed!\n");
		goto SvrSockDone;
	}
	// listen on the bound socket
	if ((sockErr = NetDll_listen(XNCALLER_SYSAPP, svrSock, 2)) != S_OK) {
		RPCDebugPrint("RPC", "NetDll_listen failed!\n");
		goto SvrSockDone;
	}

	while (true) {
		SOCKET cliSock = NetDll_accept(XNCALLER_SYSAPP, svrSock, NULL, NULL);
		if (cliSock == INVALID_SOCKET) {
			RPCDebugPrint("RPC", "NetDll_accept failed!\n");
			goto SvrSockDone;
		}

		// InfoPrint("Creating RPC client thread...\n");
		HANDLE hThread;
		DWORD dwThread;
		ExCreateThread(&hThread, 0, &dwThread, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)RPCClientThread, (PVOID)cliSock, 2);
		SetThreadPriority(hThread, THREAD_PRIORITY_ABOVE_NORMAL);
		XSetThreadProcessor(hThread, 4);
		ResumeThread(hThread);
		CloseHandle(hThread);
	}

SvrSockDone:
	NetDll_shutdown(XNCALLER_SYSAPP, svrSock, SD_BOTH);
	NetDll_closesocket(XNCALLER_SYSAPP, svrSock);
	WSACleanup();
}

BOOL RPCServerStartup() {
	RGLPrint("INFO", "Initializing RPC server...\n");

	HANDLE hThread;
	DWORD dwThread;
	ExCreateThread(&hThread, 0, &dwThread, (PVOID)XapiThreadStartup, (LPTHREAD_START_ROUTINE)RPCServerThread, 0, 2);
	SetThreadPriority(hThread, THREAD_PRIORITY_ABOVE_NORMAL);
	XSetThreadProcessor(hThread, 4);
	ResumeThread(hThread);
	CloseHandle(hThread);

	return TRUE;
}