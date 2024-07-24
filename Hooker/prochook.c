#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <winuser.h>
#include <tchar.h>
#include <Psapi.h>

#define KEY "TALTULON"
#define NKEY "MOSKO"
#define PROCNAME "notepad"

HHOOK _hook;
HWND hwnd;
KBDLLHOOKSTRUCT kbdStruct;
INPUT ip;
DWORD pid;
int index;


// This function replaces the string @KEY with the string @NKEY
// On your screen, demos a keyboard. 
int ChangeStr()
{
	ip.type = INPUT_KEYBOARD;
	ip.ki.wScan = 0;
	ip.ki.time = 0;
	ip.ki.dwExtraInfo = 0;
	ip.ki.wVk = VK_BACK;

	// loop for deleting the user input
	for (int i = 0; i < strlen(KEY); i++) {
		ip.ki.dwFlags = 0;
		SendInput(1, &ip, sizeof(INPUT));
		ip.ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, &ip, sizeof(INPUT));
	}

	// loop for inserting our input
	for (int i = 0; i < strlen(NKEY); i++) {
		ip.ki.wVk = NKEY[i];
		ip.ki.dwFlags = 0;
		SendInput(1, &ip, sizeof(INPUT));
		ip.ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, &ip, sizeof(INPUT));
	}
	// Exit normally
	return 0;
}


// This function what process is our keyboard hook being
// triggered for. If the path of the process executable
// contains the value @PROCNAME, return TRUE.
BOOL CheckProc() {
	hwnd = GetForegroundWindow();
	GetWindowThreadProcessId(hwnd, &pid);
	HANDLE Handle = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		pid
	);
	if (Handle)
	{
		TCHAR Buffer[MAX_PATH];
		if (GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH))
		{
			if (_tcsstr(Buffer, _T(PROCNAME))) {
				return TRUE;
			}
		}
		CloseHandle(Handle);
	}
	return FALSE;
}


// This function is the hook function, it captures events of type
// WM_KEYDOWN & WM_KEYUP. the function checks f a sequence of chars
// has been written by a user in the context of a specific process
// check by CheckProc. If the entire sequence has been written it 
// calls ChangeStr.
LRESULT __stdcall Hooker(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode >= 0) {
		if (CheckProc()) {
			if (wParam == WM_KEYDOWN) {

				kbdStruct = *((KBDLLHOOKSTRUCT*)lParam);
				if (kbdStruct.vkCode == KEY[index]) {
					index++;
				}
				else if (kbdStruct.vkCode == VK_BACK && index > 0) {
					index--;
				}
				else {
					index = 0;
				}
			}
			else if (wParam == WM_KEYUP) {
				if (index == strlen(KEY)) {
					ChangeStr();
				}
			}
		}
	}
	return CallNextHookEx(_hook, nCode, wParam, lParam);
}

// This function releases the hook set in main.
__cdecl ReleaseHook()
{
	UnhookWindowsHookEx(_hook);
}

// This program changes the write of @KEY string with the write of @NKEY string
// for a certain process, using windows hooks.
int main(int argc, char* argv[]) {
	index = 0;
	if (!(_hook = SetWindowsHookExA(WH_KEYBOARD_LL, Hooker, NULL, 0))) {
		MessageBoxA(NULL,"Failed to install hook :(", "Error", MB_ICONERROR);
	}
	MSG msg;
	
	// This exists because i am lazy and i want the program to
	// run until i manually terminate it.
	while (GetMessage(&msg, NULL, 0, 0))
	{

	}
	return 0;
}