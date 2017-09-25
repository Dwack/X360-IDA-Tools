// IDAX360PPCCOMPILERPLGN.cpp : Defines the entry point for the console application.
//

/*
	>Open IDA notepad for user to input their patches
	>Save text from notepad into a file to load into the PPC compilers
	>load finished .patch file back into IDA and patch into database

	** thanks to
	http://www.cplusplus.com/forum/general/102587/#msg551994
	** for example of executing batch from cmd

	** ppc2asm folder gets copied into your IDA folder **
*/

#include "ppc_plgn.h"

/***************************************************************************************************
*
*	FUNCTION		PluginStartup
*
*	DESCRIPTION		Determines whether this plugin will work with the current database.
*
*					IDA will call this function only once. If this function returns PLUGIN_SKIP,
*					IDA will never load it again. If it returns PLUGIN_OK, IDA will unload the plugin
*					but remember that the plugin agreed to work with the database. The plugin will
*					be loaded again if the user invokes it by pressing the hotkey or selecting it
*					from the menu. After the second load, the plugin will stay in memory.
*
***************************************************************************************************/

int idaapi PluginStartup(void)
{
	// only works with PPC code :)
	if (ph.id != PLFM_PPC)
		return PLUGIN_SKIP;

	// if PPC then this plugin is OK to use
	return PLUGIN_OK;
}

void idaapi PluginShutdown(void)
{
	// any cleanup code that needs to be done on exit goes here
}

/***************************************************************************************************
*
*	FUNCTION		PluginMain
*
*	DESCRIPTION		This is the main function of plugin.
*					Param is an input arguement specified in plugins.cfg file.
*                   (The default is zero.)
*
***************************************************************************************************/

void idaapi PluginMain(int param)
{
	ea_t start_addr;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	
	start_addr = get_screen_ea();
	char kxam[1024];
	sprintf_s(kxam, 1024, ".include \"macros.S\"\n\t.globl _start\n_start:\nMAKEPATCH 0x%08X\n0:\n \n9:\n.long 0xFFFFFFFF\n.end\n", start_addr);
	char* txt = asktext(1024, NULL, kxam, "Add your KXAM style patches here.....");
	TCHAR szTempPathBuffer[MAX_PATH];
	// F:\Program Files (x86)\IDAPro6.6\idaq.exe
	GetModuleFileName(NULL, szTempPathBuffer, MAX_PATH);
	// Get the position of the last slash
	char *last_slash = strrchr(szTempPathBuffer, '\\');

	// get rid of the filename
	*(last_slash + 1) = '\0';
	// combine our new strings
	char new_path[MAX_PATH];

	sprintf_s(new_path, MAX_PATH, "%sppc2asm\\ppc2asm.S", szTempPathBuffer);
	FILE* patch = qfopen(new_path, "w+");
	if (patch != NULL)
	{
		//Created FILE* continue...
		int aa = qfwrite(patch, txt, strnlen_s(txt, 1024));
		qfclose(patch);
	}
	// Get the path to our .bat file
	sprintf_s(new_path, MAX_PATH, "%sppc2asm\\ppc2asm.bat", szTempPathBuffer);

	TCHAR systemDirPath[MAX_PATH] = _T("");
	GetSystemDirectory(systemDirPath, sizeof(systemDirPath) / sizeof(_TCHAR));

	// path to cmd.exe, path to batch file, plus some space for quotes, spaces, etc.
	TCHAR commandLine[2 * MAX_PATH + 16] = _T("");

	_sntprintf_s(commandLine, sizeof(commandLine) / sizeof(_TCHAR),
		_T("\"%s\\cmd.exe\" /C \"%s\""), systemDirPath, new_path);
	if (!CreateProcess(NULL,
		commandLine,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi)
		)
	{
		msg("CreateProcess failed (%d)\n", GetLastError());
		return;
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// Successfully builds kxam style patch file
	// Now load it and apply it!
	sprintf_s(new_path, MAX_PATH, "%sppc2asm\\ppc2asm.bin", szTempPathBuffer);
	patch = qfopen(new_path, "r");
	if (patch != NULL)
	{
		linput_t* li_patch = make_linput(patch);
		qltell(li_patch);

		DWORD addr, numPatches;
		while (true)
		{
			// Read our patch addr
			lreadbytes(li_patch, &addr, 4, true);
			msg("addr = 0x%08X\n", addr);
			if (addr == 0xffffffff)
			{
				break;
			}
			// Read num of patches
			lreadbytes(li_patch, &numPatches, 4, true);
			msg("numPatches = 0x%08X\n", numPatches);
			// Read patch data into buffer
			BYTE* pbPatches = (BYTE*)qalloc(numPatches * sizeof(DWORD));
			int ret = lreadbytes(li_patch, pbPatches, numPatches * sizeof(DWORD), true);

			// Apply our patches	
			msg("Trying to patch %08X with %i bytes\n", addr, (numPatches * sizeof(DWORD)));
			file2base(li_patch, 8, addr, (addr + (numPatches * sizeof(DWORD))), 0);
			qfree(pbPatches);
			msg("Re-Analyzing area: 0x%08X\n", addr);
			analyze_area(addr, (addr + (numPatches * sizeof(DWORD))));
		}
		
		unmake_linput(li_patch);
		qfclose(patch);
	}
}

/***************************************************************************************************
*
*	Strings required for IDA Pro's PLUGIN descriptor block
*
***************************************************************************************************/

const char G_PLUGIN_COMMENT[] = "PPC to ASM patcher";
const char G_PLUGIN_HELP[] = "This plugin assists in converting PPC instructions into their relevant ASM code.\n"
"It then inserts the compiled code into the IDA database.\n";
const char G_PLUGIN_NAME[] = "PPC To ASM";
const char G_PLUGIN_HOTKEY[] = "CTRL + X";

/***************************************************************************************************
*
*	This 'PLUGIN' data block is how IDA Pro interfaces with this plugin.
*
***************************************************************************************************/
plugin_t PLUGIN =
{
	// values
	IDP_INTERFACE_VERSION,
	0,						// plugin flags	

	// functions
	PluginStartup,			// initialize
	PluginShutdown,			// terminate. this pointer may be NULL.
	PluginMain,				// invoke plugin

	// strings
	(char*)G_PLUGIN_COMMENT,// long comment about the plugin (may appear on status line or as a hint)
	(char*)G_PLUGIN_HELP,	// multiline help about the plugin
	(char*)G_PLUGIN_NAME,	// the preferred short name of the plugin, used by menu system
	(char*)G_PLUGIN_HOTKEY	// the preferred hotkey to run the plugin
};
