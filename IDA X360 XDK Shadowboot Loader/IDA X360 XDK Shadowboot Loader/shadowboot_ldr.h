//#pragma once
#include <stdio.h>
#include <stdlib.h>
//#include <Windows.h>
#include "XeCrypt.h"

#include "idaldr.h"
#include "search.hpp"
#include "typeinf.hpp"
#include "struct.hpp"
#include "fdi.h"
#include "cryptlib\lzx.h"

FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE * __cdecl __iob_func(void) { return _iob; }



const BYTE zeroKey[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const BYTE blkey[] = {
	0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7,
	0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA
};

typedef struct CXEBOOTLOADERHEADER
{
	WORD wMagic;
	WORD wBuild;
	WORD wQfe;
	WORD wFlags;
	DWORD dwEntrypoint;
	DWORD dwLength;
} CXeBootloaderHeader, *pCXeBootloaderHeader;

typedef struct CXEBOOTLOADER
{
	CXeBootloaderHeader blHdr;
}CXeBootloader, *pCXeBootloader;

class CXeBootloaderFlash : public CXeBootloader
{
	BYTE bCopyrightSign;
	CHAR bCopyright[0x3F]; // 0x3F
	BYTE bReserved[0x10]; // 0x10
	DWORD dwKeyVaultLength;
	DWORD dwSysUpdateAddr;
	WORD wSysUpdateCount;
	WORD wKeyVaultVersion;
	DWORD dwKeyVaultAddr;
	DWORD dwFileSystemAddr;
	DWORD dwSmcConfigAddr;
	DWORD dwSmcLength;
	DWORD dwSmcAddr;
};

typedef struct BOOTLOADER_2BL_PERBOX
{
	BYTE bPairingData[0x3];  // 0x00:0x03 bytes
	BYTE bLockDownValue;// 0x03:0x01 bytes
	BYTE bReserved[0xC];     // 0x04:0x0C bytes
	BYTE bPerBoxDigest[0x10]; // 0x10:0x10 bytes
} BOOTLOADER_2BL_PERBOX, *PBOOTLOADER_2BL_PERBOX;

typedef struct BOOTLOADER_2BL_ALLOWDATA
{
	BYTE bConsoleType; // 0x00:0x01
	BYTE bConsoleSequence; // 0x01:0x01
	WORD wConsoleSequenceAllow; // 0x02:0x02
} BOOTLOADER_2BL_ALLOWDATA, *PBOOTLOADER_2BL_ALLOWDATA;
