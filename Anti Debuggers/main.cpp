#include <iostream>
#include "protector/protector.hpp"

/* What you need to do to use anti debugger is very simple, you just need to call it with this code. */
/* Contact Discord : Emree#2023 */

int main()
{
	VMProtectBeginUltra("Main Function");

	/* Set Protector Detection Scan Time (1000MS = 1 Second) */
	/* I do not recommend reducing this time, if the number is too low the CPU usage will increase. */
	protector::scan_detection_time = 1000;

	/* Some protection features */
	protector::scan_exe = true;
	protector::scan_title = true;
	protector::scan_driver = true;

	/* This feature does killdbg all the time, but it's not very optimized, so I don't recommend turning it on. */
	protector::loop_killdbgr = false;

	/* Activate it if you want to make the user BSOD (Blue Screen Of Death) when the debugger is detected. */
	protector::protector_bsod = false;

	/* If you want to test it, you can turn on the debug log feature. */
	protector::debug_log = true;

	/* After making all the settings, we call the protection function. */
	protector::start_protect();

	/* A few extra small debug protection functions. */
	
	// protector::anti_dbg();
	// protector::anti_dbg_2();

	while (true) {

		/*
	

		*/
		
		SleepEx(10, true); // To lower CPU usage
	}


	VMProtectEnd();
}

