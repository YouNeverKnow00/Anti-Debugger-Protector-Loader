#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <thread>
#include "VMProtectSDK.h"
#include "xorstr.hpp"
#include "bsod.h"
#include "../other/color.hpp"

namespace protector {

	/* The more you increase the value, the later it will detect it, so adjust it carefully. */
	int scan_detection_time;

	/* Variables to enable or disable Protection Features. */
	bool scan_exe;
	bool scan_title;
	bool scan_driver;
	bool loop_killdbgr;

	bool debug_log;

	/* To activate the bsod function */
	bool protector_bsod;

	std::uint32_t find_dbg(const char* proc)
	{
		auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		auto pe = PROCESSENTRY32{ sizeof(PROCESSENTRY32) };

		if (Process32First(snapshot, &pe)) {
			do {
				if (!_stricmp(proc, pe.szExeFile)) {
					CloseHandle(snapshot);
					return pe.th32ProcessID;
				}
			} while (Process32Next(snapshot, &pe));
		}
		CloseHandle(snapshot);
		return 0;
	}

	/* The function that will run after the Debugger is detected. */
	/* You can add what you want, it's up to your imagination, I added the bsod function here. */
	void debugger_detected(std::string msg)
	{
		VMProtectBeginUltra("Detected Func");

		/* If you want to debug for testing you can use */

		if (debug_log == true) {
			std::cout << termcolor::white << XorStr("<--------------------------------------->").c_str() << std::endl;
			std::cout << termcolor::green << XorStr(" Debugger detected!").c_str() << std::endl;
			std::cout << termcolor::red   << XorStr(" Debugger Name: ").c_str() << termcolor::cyan << msg << std::endl;
			std::cout << termcolor::white << XorStr("<--------------------------------------->").c_str() << std::endl;
		}

		/* Call function BSOD (Blue Screen Of Death) */
		if (protector_bsod == true) {
			get_bsod();
		}

		if (debug_log == true) {
			Sleep(2000);
		}

		/* Exit Application */
		exit(0);

		VMProtectEnd();
	}

	/* Basic Anti Debug Functions */
	void anti_dbg() {

		if (IsDebuggerPresent())
		{
			exit(1);
		}
		else
		{
			
		}
	}

	/* Basic Anti Debug Functions */
	void anti_dbg_2() {
		
		__try {
			DebugBreak();
		}
		__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ?
			EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
			
		}

	}

	/* Exe Detection Function */
	void exe_detect()
	{
		VMProtectBeginUltra("EXE Detect Function");

		if (scan_exe == true) {

			if (find_dbg(XorStr("KsDumperClient.exe").c_str()))
			{
				debugger_detected(XorStr("KsDumper").c_str());
			}
			else if (find_dbg(XorStr("HTTPDebuggerUI.exe").c_str()))
			{
				debugger_detected(XorStr("HTTP Debugger").c_str());
			}
			else if (find_dbg(XorStr("HTTPDebuggerSvc.exe").c_str()))
			{
				debugger_detected(XorStr("HTTP Debugger Service"));
			}
			else if (find_dbg(XorStr("FolderChangesView.exe").c_str()))
			{
				debugger_detected(XorStr("FolderChangesView"));
			}
			else if (find_dbg(XorStr("ProcessHacker.exe").c_str()))
			{
				debugger_detected(XorStr("Process Hacker"));
			}
			else if (find_dbg(XorStr("procmon.exe").c_str()))
			{
				debugger_detected(XorStr("Process Monitor"));
			}
			else if (find_dbg(XorStr("idaq.exe").c_str()))
			{
				debugger_detected(XorStr("IDA"));
			}
			else if (find_dbg(XorStr("ida.exe").c_str()))
			{
				debugger_detected(XorStr("IDA"));
			}
			else if (find_dbg(XorStr("idaq64.exe").c_str()))
			{
				debugger_detected(XorStr("IDA"));
			}
			else if (find_dbg(XorStr("Wireshark.exe").c_str()))
			{
				debugger_detected(XorStr("WireShark").c_str());
			}
			else if (find_dbg(XorStr("Fiddler.exe").c_str()))
			{
				debugger_detected(XorStr("Fiddler").c_str());
			}
			else if (find_dbg(XorStr("Xenos64.exe").c_str()))
			{
				debugger_detected(XorStr("Xenos64").c_str());
			}
			else if (find_dbg(XorStr("Cheat Engine.exe").c_str()))
			{
				debugger_detected(XorStr("CheatEngine"));
			}
			else if (find_dbg(XorStr("HTTP Debugger Windows Service (32 bit).exe").c_str()))
			{
				debugger_detected(XorStr("HTTP Debugger"));
			}
			else if (find_dbg(XorStr("KsDumper.exe").c_str()))
			{
				debugger_detected(XorStr("KsDumper"));
			}
			else if (find_dbg(XorStr("x64dbg.exe").c_str()))
			{
				debugger_detected(XorStr("x64DBG"));
			}
			else if (find_dbg(XorStr("x64dbg.exe").c_str()))
			{
				debugger_detected(XorStr("x64DBG"));
			}
			else if (find_dbg(XorStr("x32dbg.exe").c_str()))
			{
				debugger_detected(XorStr("x32DBG"));
			}
			else if (find_dbg(XorStr("Fiddler Everywhere.exe").c_str()))
			{
				debugger_detected(XorStr("FiddlerEverywhere"));
			}
			else if (find_dbg(XorStr("die.exe").c_str()))
			{
				debugger_detected(XorStr("DetectItEasy"));
			}
			else if (find_dbg(XorStr("Everything.exe").c_str()))
			{
				debugger_detected(XorStr("Everything.exe"));
			}

			else if (find_dbg(XorStr("OLLYDBG.exe").c_str()))
			{
				debugger_detected(XorStr("OLLYDBG"));
			}

			else if (find_dbg(XorStr("HxD64.exe").c_str()))
			{
				debugger_detected(XorStr("HxD64"));
			}

			else if (find_dbg(XorStr("HxD32.exe").c_str()))
			{
				debugger_detected(XorStr("HxD64"));
			}

			else if (find_dbg(XorStr("snowman.exe").c_str()))
			{
				debugger_detected(XorStr("Snowman"));
			}
		}

		VMProtectEnd();
	}

	/* Title Detection Function */
	void title_detect()
	{
		VMProtectBeginUltra("TitleDetect Function");

		if (scan_title == true) {

			HWND window;
			window = FindWindow(0, XorStr(("IDA: Quick start")).c_str());
			if (window)
			{
				debugger_detected(XorStr("IDA"));
			}


			window = FindWindow(0, XorStr(("Memory Viewer")).c_str());
			if (window)
			{
				debugger_detected(XorStr("CheatEngine"));
			}

			window = FindWindow(0, XorStr(("Cheat Engine")).c_str());
			if (window)
			{
				debugger_detected(XorStr("CheatEngine"));
			}

			window = FindWindow(0, XorStr(("Cheat Engine 7.2")).c_str());
			if (window)
			{
				debugger_detected(XorStr("CheatEngine"));
			}

			window = FindWindow(0, XorStr(("Cheat Engine 7.1")).c_str());
			if (window)
			{
				debugger_detected(XorStr("CheatEngine"));
			}

			window = FindWindow(0, XorStr(("Cheat Engine 7.0")).c_str());
			if (window)
			{
				debugger_detected(XorStr("CheatEngine"));
			}

			window = FindWindow(0, XorStr(("Process List")).c_str());
			if (window)
			{
				debugger_detected(XorStr("CheatEngine"));
			}

			window = FindWindow(0, XorStr(("x32DBG")).c_str());
			if (window)
			{
				debugger_detected(XorStr("x32DBG"));
			}

			window = FindWindow(0, XorStr(("x64DBG")).c_str());
			if (window)
			{
				debugger_detected(XorStr("x64DBG"));
			}

			window = FindWindow(0, XorStr(("KsDumper")).c_str());
			if (window)
			{
				debugger_detected(XorStr("KsDumper").c_str());
			}
			window = FindWindow(0, XorStr(("Fiddler Everywhere")).c_str());
			if (window)
			{
				debugger_detected(XorStr("FiddlerEverywhere"));
			}
			window = FindWindow(0, XorStr(("Fiddler Classic")).c_str());
			if (window)
			{
				debugger_detected(XorStr("FiddlerClassic"));
			}

			window = FindWindow(0, XorStr(("Fiddler Jam")).c_str());
			if (window)
			{
				debugger_detected(XorStr("FiddlerJam"));
			}

			window = FindWindow(0, XorStr(("FiddlerCap")).c_str());
			if (window)
			{
				debugger_detected(XorStr("FiddlerCap"));
			}

			window = FindWindow(0, XorStr(("FiddlerCore")).c_str());
			if (window)
			{
				debugger_detected(XorStr("FiddlerCore").c_str());
			}

			window = FindWindow(0, XorStr(("Scylla x86 v0.9.8")).c_str());
			if (window)
			{
				debugger_detected(XorStr("Scylla_x86").c_str());
			}

			window = FindWindow(0, XorStr(("Scylla x64 v0.9.8")).c_str());
			if (window)
			{
				debugger_detected(XorStr("Scylla_x64").c_str());
			}

			window = FindWindow(0, XorStr(("Scylla x86 v0.9.5a")).c_str());
			if (window)
			{
				debugger_detected(XorStr("Scylla_x86").c_str());
			}

			window = FindWindow(0, XorStr(("Scylla x64 v0.9.5a")).c_str());
			if (window)
			{
				debugger_detected(XorStr("Scylla_x64").c_str());
			}

			window = FindWindow(0, XorStr(("Scylla x86 v0.9.5")).c_str());
			if (window)
			{
				debugger_detected(XorStr("Scylla_x86").c_str());
			}

			window = FindWindow(0, XorStr(("Scylla x64 v0.9.5")).c_str());
			if (window)
			{
				debugger_detected(XorStr("Scylla_x64").c_str());
			}

			window = FindWindow(0, XorStr(("Detect It Easy v3.01")).c_str());
			if (window)
			{
				debugger_detected(XorStr("DetectItEasy").c_str());
			}

			window = FindWindow(0, XorStr(("Everything")).c_str());
			if (window)
			{
				debugger_detected(XorStr("Everything").c_str());
			}

			window = FindWindow(0, XorStr(("OllyDbg")).c_str());
			if (window)
			{
				debugger_detected(XorStr("OllyDbg"));
			}

			window = FindWindow(0, XorStr(("OllyDbg")).c_str());
			if (window)
			{
				debugger_detected(XorStr("OllyDbg"));
			}

			window = FindWindow(0, XorStr(("HxD")).c_str());
			if (window)
			{
				debugger_detected(XorStr("HxD"));
			}

			window = FindWindow(0, XorStr(("Snowman")).c_str());
			if (window)
			{
				debugger_detected(XorStr("HxD"));
			}

		}

		VMProtectEnd();
	}

	/* Driver Detection Function */
	void driver_detect()
	{
		VMProtectBeginUltra("Driver Detect");

		if (scan_driver == true) {

			const TCHAR* devices[] = {
		_T("\\\\.\\NiGgEr"),
		_T("\\\\.\\KsDumper")
			};

			WORD iLength = sizeof(devices) / sizeof(devices[0]);
			for (int i = 0; i < iLength; i++)
			{
				HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				TCHAR msg[256] = _T("");
				if (hFile != INVALID_HANDLE_VALUE) {

					debugger_detected(XorStr("Driver Detected").c_str());

				}
				else
				{

				}
			}

		}
		VMProtectEnd();
	}

	void one_killdbg()
	{
		VMProtectBeginUltra("KillDBG");

		/* If there is anything else you want to add, you can write it here. */
		system(XorStr("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1").c_str());
		system(XorStr("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1").c_str());
		system(XorStr("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1").c_str());

		VMProtectEnd();
	}

	void loop_killdbg()
	{
		VMProtectBeginUltra("Loop KillDBG");

		/*  For example, if you type 60 here, the killdebuger will run every 60 seconds. */
		std::this_thread::sleep_for(std::chrono::seconds(60));
		/* If there is anything else you want to add, you can write it here. */
		system(XorStr("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1").c_str());
		system(XorStr("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1").c_str());
		system(XorStr("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1").c_str());

		VMProtectEnd();
	}

	void call_loop_killdbg() {

		if (loop_killdbgr == TRUE) {

			while (true) {

				protector::loop_killdbg();

				SleepEx(1, true);
			}

		}

	}

	/* Start Protector Main Function */
	void protector()
	{
		/* We do it once. */
		one_killdbg();
		while (true) {

			/* Protector Functions */
			protector::exe_detect();
			protector::title_detect();
			protector::driver_detect();

			/* Optimize (CPU) Required to reduce usage. */
			SleepEx(scan_detection_time, true);
		}
	}

	void start_protect() {

		/* Create threads for functions. */
		std::thread(protector).detach();

		std::thread(call_loop_killdbg).detach();

	}


};
