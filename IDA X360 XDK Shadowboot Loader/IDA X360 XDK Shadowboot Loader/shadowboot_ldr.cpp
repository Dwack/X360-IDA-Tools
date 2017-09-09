#include "shadowboot_ldr.h"


#define f_PPC 0x4252

extern "C"
{
	FNALLOC(Kmem_alloc)
	{
		return malloc(cb);
	}

	FNFREE(Kmem_free)
	{
		free(pv);
	}
}

#ifdef _DEBUG
int msg(const char *format, ...);
#else
#define msg
#endif

#define EXTRACT_WORD(BUFFER, BASE, RESULT)        RESULT = 0; \
  RESULT   = BUFFER[BASE];                                    \
  RESULT <<= 8;                                               \
  RESULT  |= BUFFER[BASE+1];

// Global Shadowboot ROM headers
CXeBootloaderHeader hdr, _2bl_hdr, _3bl_hdr, _4bl_hdr, _5bl_hdr;
BYTE _sbKey[0x10], _scKey[0x10], _sdKey[0x10], _seKey[16];
ea_t total_size;

void hexDump(char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		msg("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				msg("  %s\n", buff);

			// Output the offset.
			msg("  %04x ", i);
		}

		// Now the hex code for the specific character.
		msg(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		msg("   ");
		i++;
	}

	// And print the final ASCII bit.
	msg("  %s\n", buff);
}

ea_t Get2blAddr()
{
	return hdr.dwEntrypoint;
}

ea_t Get3blAddr()
{
	return hdr.dwEntrypoint + _2bl_hdr.dwLength;
}

ea_t Get4blAddr()
{
	return hdr.dwEntrypoint + _2bl_hdr.dwLength + _3bl_hdr.dwLength;
}

ea_t Get5blAddr()
{
	return hdr.dwEntrypoint + _2bl_hdr.dwLength + _3bl_hdr.dwLength + _4bl_hdr.dwLength;
}

int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
	if (n) return NULL;
	lreadbytes(li, &hdr.wMagic, 2, true);
	if (hdr.wMagic != 0xFF4F)
	{
		msg("Invalid Header...exiting\n");
		return NULL;
	}

	lreadbytes(li, &hdr.wBuild, 2, true);
	lreadbytes(li, &hdr.wQfe, 2, true);
	lreadbytes(li, &hdr.wFlags, 2, true);
	lreadbytes(li, &hdr.dwEntrypoint, 4, true);
	lreadbytes(li, &hdr.dwLength, 4, true);
	msg("Bootloader ROM Header\n");
	msg("Magic: %X | Qfe: %X| Flags: %X | Entry: %08X | Size: %08X\n", hdr.wMagic, hdr.wQfe, hdr.wFlags, hdr.dwEntrypoint, hdr.dwLength);
	qstrncpy(fileformatname, "X360 Shadowboot ROM", MAX_FILE_FORMAT_NAME);
	return 1;
}

void SetupRegSaves()
{
	msg("in REGISTER\n");
	char funcName[255];
	ea_t currAddr, i;
	for (currAddr = 0; currAddr != BADADDR; currAddr += 4)
	{
		currAddr = find_binary(currAddr, total_size, "F9 C1 FF 68 F9 E1 FF 70", 16, SEARCH_DOWN);
		if (currAddr == BADADDR) break;
		for (i = 14; i <= 31; i++)
		{
			if (i != 31) add_func(currAddr, currAddr + 4);
			else add_func(currAddr, currAddr + 0xC);
			sprintf(funcName, "__Save_R12_%d_thru_31", i);
			set_name(currAddr, funcName);
			currAddr += 4;
		}
	}

	for (currAddr = 0; currAddr != BADADDR; currAddr += 4)
	{
		currAddr = find_binary(currAddr, total_size, "E9 C1 FF 68 E9 E1 FF 70", 16, SEARCH_DOWN);
		if (currAddr == BADADDR) break;
		for (i = 14; i <= 31; i++)
		{
			if (i != 31) add_func(currAddr, currAddr + 4);
			else add_func(currAddr, currAddr + 0xC);
			sprintf(funcName, "__Rest_R12_lr_%d_thru_31", i);
			set_name(currAddr, funcName);
			currAddr += 4;
		}
	}
}

void AddStructures()
{
	opinfo_t b;
	tid_t a = add_struc(BADADDR, "XECRYPT_RC4_STATE");
	add_struc_member(get_struc(a), "S", BADADDR, 1, &b, 256);
	add_struc_member(get_struc(a), "i", BADADDR, 1, &b, 1);
	add_struc_member(get_struc(a), "j", BADADDR, 1, &b, 1);

	a = add_struc(BADADDR, "XECRYPT_SHA_STATE");
	add_struc_member(get_struc(a), "count", BADADDR, 0x20000400, &b, 4); // FF_DATA | FF_DWRD
	add_struc_member(get_struc(a), "state", BADADDR, 0x20000400, &b, 4 * 5);
	add_struc_member(get_struc(a), "buffer", BADADDR, 0, &b, 64);

	a = add_struc(BADADDR, "XECRYPT_HMACSHA_STATE");
	add_struc_member(get_struc(a), "ShaStste", BADADDR, 0, &b, 0x58 * 2);

	a = add_struc(BADADDR, "XECRYPT_SIG");
	add_struc_member(get_struc(a), "aqwPad", BADADDR, 0x30000400, &b, 8 * 28); // FF_DATA | FF_QWRD
	add_struc_member(get_struc(a), "bOne", BADADDR, 0, &b, 1);
	add_struc_member(get_struc(a), "abSalt", BADADDR, 0, &b, 10);
	add_struc_member(get_struc(a), "abHash", BADADDR, 0, &b, 20);
	add_struc_member(get_struc(a), "bEnd", BADADDR, 0, &b, 1);

	a = add_struc(BADADDR, "XECRYPT_RSA");
	add_struc_member(get_struc(a), "cqw", BADADDR, 0x20000400, &b, 4); // FF_DATA | FF_DWRD
	add_struc_member(get_struc(a), "dwPubExp", BADADDR, 0x20000400, &b, 4);
	add_struc_member(get_struc(a), "qwReserved", BADADDR, 0x30000400, &b, 8);

	b.tid = a;
	a = add_struc(BADADDR, "XECRYPT_RSAPUB_2048");
	add_struc_member(get_struc(a), "Rsa", BADADDR, 0x60000000, &b, 16); // FF_DATA | FF_DWRD
	add_struc_member(get_struc(a), "aqwM", BADADDR, 0x30000400, &b, 8 * 32);

	a = add_struc(BADADDR, "BOOTLOADER_2BL_PERBOX");
	add_struc_member(get_struc(a), "bPairingData", BADADDR, 1, &b, 3);
	add_struc_member(get_struc(a), "bLockDownValue", BADADDR, 1, &b, 1);
	add_struc_member(get_struc(a), "bReserved", BADADDR, 1, &b, 0xC);
	add_struc_member(get_struc(a), "bPerBoxDigest", BADADDR, 1, &b, 0x10);

	a = add_struc(BADADDR, "BOOTLOADER_2BL_ALLOWDATA");
	add_struc_member(get_struc(a), "bConsoleType", BADADDR, 1, &b, 1);
	add_struc_member(get_struc(a), "bConsoleSequence", BADADDR, 1, &b, 1);
	add_struc_member(get_struc(a), "wConsoleSequenceAllow", BADADDR, 0x10000400, &b, 2);
}

void SetupVariousFunctions()
{
	ea_t post = find_binary(0, total_size, "78 84 C1 C6 F8 83 00 00 4E 80 00 20", 16, SEARCH_DOWN);
	set_name(post, "BlpPOST_Out");
	apply_cdecl(post, "void BlpPOST_Out(_QWORD post_addr, _BYTE post_code);");
	post = find_binary(0, total_size, "38 00 00 00 7C 18 23 A6 4B FF FF F8 00 00 00 00", 16, SEARCH_DOWN);
	set_name(post, "BlpPanic");
	post = find_binary(0, total_size, "3D 40 67 45 3D 20 EF CD 3D 00 98 BA 3C E0 10 32", 16, SEARCH_DOWN);
	set_name(post, "XeCryptShaInit");
	apply_cdecl(post, "void XeCryptShaInit(XECRYPT_SHA_STATE * pShaState);");
	auto_make_proc(post);
	post = find_binary(0, total_size, "F8 21 FF 71 7C 7D 1B 78 7C BF 2B 78 7C 9E 23 78", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptShaUpdate");
	apply_cdecl(post - 8, "void XeCryptShaUpdate(XECRYPT_SHA_STATE * pShaState, const _BYTE * pbInp, _DWORD cbInp);");
	post = find_binary(0, total_size, "F8 61 FF F8 54 66 07 7E 28 06 00 00 20 C6 00 08", 16, SEARCH_DOWN);
	set_name(post, "memcpy");
	apply_cdecl(post, "void* memcmpy(void* ptrDest, void* ptrSrc, int num);");
	post = find_binary(NULL, total_size, "38 05 00 01 7C 09 03 A6 60 66 00 00 48 00 00 10 38 A5 FF FF", 16, SEARCH_DOWN);
	set_name(post, "memset");
	apply_cdecl(post, "void* memset(void* ptr, int value, int num);");
	post = find_binary(0, total_size, "F8 21 FE 21 7C 77 1B 78  7C 83 23 78 38 A0 00 10", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptShaTransform");
	apply_cdecl(post - 8, "void XeCryptShaTransform(_DWORD* pState, _BYTE * pbBuf);");
	post = find_binary(0, total_size, "28 05 00 00 7F 23 20 40 7C 83 20 50 7C A9 03 A6 4D C2 00 20 4D DA 00 20  80 C3 00 00 7C C3 21 2E 38 63 00 04 43 20 FF F4  4E 80 00 20", 16, SEARCH_DOWN);
	set_name(post, "XeCryptBnDw_Copy");
	post = find_binary(0, total_size, "F8 21 FF 61 7C 7F 1B 78 7C 99 23 78 3B DF 00 18", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptShaFinal");
	apply_cdecl(post - 8, "void XeCryptShaFinal(XECRYPT_SHA_STATE * pShaState, _BYTE * pbOut, _DWORD cbOut);");
	post = find_binary(0, total_size, "3C C0 00 01 3C E0 08 08 60 C6 02 03 60 E7 08 08", 16, SEARCH_DOWN);
	set_name(post, "XeCryptRc4Key");
	apply_cdecl(post, "void XeCryptRc4Key(XECRYPT_RC4_STATE * pRc4State, const _BYTE * pbKey, _DWORD cbKey);");
	post = find_binary(0, total_size, "28 05 00 00 4D C2 00 20 7C A9 03 A6 88 C3 01 00 88 E3 01 01", 16, SEARCH_DOWN);
	set_name(post, "XeCryptRc4Ecb");
	apply_cdecl(post, "void XeCryptRc4Ecb(XECRYPT_RC4_STATE * pRc4State, _BYTE * pbInpOut, _DWORD cbInpOut);");
	post = find_binary(NULL, total_size, "F8 21 FF 01 3D 60 67 45  7C 7F 1B 78 61 67 23 01", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptHmacShaInit");
	apply_cdecl(post - 8, "void XeCryptHmacShaInit(XECRYPT_HMACSHA_STATE * pHmacShaState, const _BYTE * pbKey, _DWORD cbKey);");
	post = find_binary(NULL, total_size, "F8 21 FE C1 7C BE 2B 78  7C 85 23 78 7C 64 1B 78", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptHmacSha");
	apply_cdecl(post - 8, "void XeCryptHmacSha(const _BYTE * pbKey, _DWORD cbKey, const _BYTE * pbInp1, _DWORD cbInp1, const _BYTE * pbInp2, _DWORD cbInp2, const _BYTE * pbInp3, _DWORD cbInp3, _BYTE * pbOut, _DWORD cbOut);");
	post = find_binary(NULL, total_size, "F8 21 FF 81 7C 9D 23 78  7C BC 2B 78 38 A0 00 00", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptHmacShaFinal");
	apply_cdecl(post - 8, "void XeCryptHmacShaFinal(XECRYPT_HMACSHA_STATE * pHmacShaState, _BYTE * pbOut, _DWORD cbOut);");
	post = find_binary(NULL, total_size, "F8 21 FF 01 39 60 00 00 7C 9E 23 78 7C 7F 1B 78", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptRotSumSha");
	apply_cdecl(post - 8, "void XeCryptRotSumSha(const _BYTE * pbInp1, _DWORD cbInp1, const _BYTE * pbInp2, _DWORD cbInp2, _BYTE * pbOut, _DWORD cbOut);");
	post = find_binary(0, total_size, "E8 E3 00 00 E9 23 00 08 E8 C3 00 10 E9 43 00 18", 16, SEARCH_DOWN);
	set_name(post, "XeCryptRotSum");
	//post = find_binary(0, total_size, "2B 1F 00 00 41 9A 00 14  7F E5 FB 78 7F C4 F3 78 38 61 00 50", 16, SEARCH_DOWN);
	//set_name(post, "XeCryptSha");
	// XeCryptSha(const BYTE * pbInp1, DWORD cbInp1, const BYTE * pbInp2, DWORD cbInp2, const BYTE * pbInp3, DWORD cbInp3, BYTE * pbOut, DWORD cbOut);
	// 2B 1F 00 00 41 9A 00 14  7F E5 FB 78 7F C4 F3 78 38 61 00 50
	post = find_binary(NULL, total_size, "F9 81 FF F8 FB E1 FF F0  F8 21 FF 71 39 60 00 14", 16, SEARCH_DOWN);
	set_name(post - 4, "XeCryptHmacShaVerify");
	apply_cdecl(post - 4, "bool XeCryptHmacShaVerify(const _BYTE * pbKey, _DWORD cbKey, const _BYTE * pbInp1, _DWORD cbInp1, const _BYTE * pbInp2, _DWORD cbInp2, const _BYTE * pbInp3, _DWORD cbInp3, const _BYTE * pbVer, _DWORD cbVer);");

	post = find_binary(0, total_size, "2C 05 00 00 7C A9 03 A6  38 E0 00 00 41 82 00 24 88 C4 00 00", 16, SEARCH_DOWN);
	set_name(post, "XeCryptMemDiff");
	apply_cdecl(post, "bool XeCryptMemDiff(const _BYTE * pbInp1, const _BYTE * pbInp2, _DWORD cbInp);");

	post = find_binary(0, total_size, "2C 05 00 00 7C A9 03 A6  38 E0 00 00 41 82 00 24 88 C4 00 00", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptBnQwBeSigFormat");
	apply_cdecl(post - 8, "void XeCryptBnQwBeSigFormat(XECRYPT_SIG * pSig, const _BYTE * pbHash, const _BYTE * pbSalt);");

	// XeCryptBnQwNeModInv
	// 1D 63 00 03 69 6A 00 02  39 20 00 05 7D 6A 19 D2
	// 21 6B 00 01 39 0B 00 01  55 29 08 3C 7D 6B 59 D2
	post = find_binary(0, total_size, "1D 63 00 03 69 6A 00 02  39 20 00 05 7D 6A 19 D2", 16, SEARCH_DOWN);
	set_name(post, "XeCryptBnQwNeModInv");
	apply_cdecl(post, "_QWORD XeCryptBnQwNeModInv(_QWORD qw);");

	// XeCryptBnQwNeModMul - 40
	// 38 00 00 0B 7C 09 03 A6  38 00 00 00 39 C1 00 50

	// XeCryptBnQw_Copy
	// 28 05 00 00 7F 23 20 40  7C A9 03 A6 7C 83 20 50

	//XeCryptBnQwBeSigVerify(XECRYPT_SIG * pSig, const BYTE * pbHash, const BYTE * pbSalt, const XECRYPT_RSA * pRsa);

}

void LabelHeader()
{
	doWord(0, 2);
	doWord(2, 2);
	doWord(4, 2);
	doWord(6, 2);
	doDwrd(8, 4);
	doDwrd(0xC, 4);
	set_name(0, "Magic");
	set_name(2, "Version");
	set_name(4, "Qfe");
	set_name(6, "Flags");
	set_name(8, "Entry");
	set_name(0xC, "Size");
	op_chr(0, 0);
	op_dec(2, 0);
}

void SetupDatabaseCompilerInfo()
{
	inf.baseaddr = 0;
	//set_compiler_id(COMP_MS);
	compiler_info_t tt;
	tt.cm = 0x02;
	tt.size_i = 4;
	tt.size_b = 4;
	tt.size_e = 4;
	tt.defalign = 1;
	tt.id = COMP_MS;
	set_compiler(tt, SETCOMP_OVERRIDE);
	inf.filetype = f_PPC;
	inf.lflags |= LFLG_PC_FLAT;
	inf.af2 = inf.af2 & ~AF2_FTAIL;
}

//Add per BL data
void AddBLData(WORD Magic)
{
	// SB
	if (Magic == 0x5342)
	{
		doByte(0x10, 0x10);
		set_name(0x10, "pb2blNonce");
		tid_t s = get_struc_id("BOOTLOADER_2BL_PERBOX");
		doStruct(0x20, 0x20, s);
		set_name(0x20, "blPerBoxData");
		doByte(0x40, 0x100);
		set_name(0x40, "pbSignature");
		doByte(0x140, 0x110);
		set_name(0x140, "pbAesInvData");
		doQwrd(0x250, 8);
		set_name(0x250, "ulPostOutputAddr");
		doQwrd(0x40 + 0x218, 8);
		set_name(0x40 + 0x218, "ulSbFlashAddr");
		doQwrd(0x40 + 0x220, 8);
		set_name(0x40 + 0x220, "ulSocMmioAddr");
		doStruct(0x40 + 0x228, 0x110, get_struc_id("XECRYPT_RSAPUB_2048"));
		set_name(0x40 + 0x228, "pbRsaPublicKey");
		doByte(0x40 + 0x228 + 0x110, 0x10);
		set_name(0x40 + 0x228 + 0x110, "pb3BLNonce");
		doASCI(0x40 + 0x228 + 0x120, 0xA);
		set_name(0x40 + 0x228 + 0x120, "pb3BLSalt");
		doASCI(0x4A + 0x228 + 0x120, 0xA);
		set_name(0x4A + 0x228 + 0x120, "pb4BLSalt");
		doByte(0x4A + 0x228 + 0x12A, 0x14);
		set_name(0x4A + 0x228 + 0x12A, "pb4BLDigest");
		doStruct(0x4A + 0x228 + 0x12A + 0x14, 4, get_struc_id("BOOTLOADER_2BL_ALLOWDATA"));
		set_name(0x4A + 0x228 + 0x12A + 0x14, "blAllowData");
		doDwrd(0x4A + 0x228 + 0x12A + 0x18, 4);
		set_name(0x4A + 0x228 + 0x12A + 0x18, "dwPadding");
	}
	// SC
	else if (Magic == 0x5343)
	{
		doByte(0x20, 0x100);
		set_name(0x20, "pbSignature");
	}
	// SD
	else if (Magic == 0x5344)
	{
		doByte(0x20, 0x100);
		set_name(0x20, "pbSignature");
		doStruct(0x120, 0x110, get_struc_id("XECRYPT_RSAPUB_2048"));
		set_name(0x120, "pbRsaPublicKey");
		doByte(0x230, 0x10);
		set_name(0x230, "pb6BLNone");
		doASCI(0x240, 0xA);
		set_name(0x240, "pb6BLSalt");
		doWord(0x24A, 0x2);
		set_name(0x24A, "wPadding");
		doByte(0x24C, 0x14);
		set_name(0x24C, "pb5BLDigest");
		doByte(0x24C + 0x14, 1);
		set_name(0x24C + 0x14, "bUsesCpuKey");
	}
}

void Load2bl(linput_t *_li)
{
	SetupDatabaseCompilerInfo();
	set_processor_type("ppc", SETPROC_ALL | SETPROC_FATAL);
	msg("2bl Header Magic: %X | Qfe: %X | Flags: %X | Entry: %08X | Size: %08X\n", _2bl_hdr.wMagic, _2bl_hdr.wQfe, _2bl_hdr.wFlags, _2bl_hdr.dwEntrypoint, _2bl_hdr.dwLength);
	BYTE* _2bl_buf = (BYTE*)malloc(_2bl_hdr.dwLength);
	// reset position
	qlseek(_li, Get2blAddr()); // start of 2bl
	lreadbytes(_li, _2bl_buf, _2bl_hdr.dwLength, false);
	// decrypt it
	XeCryptHmacSha(blkey, sizeof(blkey), &_2bl_buf[0x10], 0x10, NULL, 0, NULL, 0, _sbKey, 0x10);
	XeCryptRc4(_sbKey, 0x10, &_2bl_buf[0x20], _2bl_hdr.dwLength - 0x20);
	// add it to database
	mem2base(_2bl_buf, 0, _2bl_hdr.dwLength, -1);
	set_selector(0, 0);
	add_segm(0, 0, _2bl_hdr.dwEntrypoint, ".2bl_header", "DATA");
	set_selector(0, 0);
	add_segm(0, _2bl_hdr.dwEntrypoint, _2bl_hdr.dwLength, ".2bl_rom", "CODE");
	auto_make_proc(_2bl_hdr.dwEntrypoint);
	total_size = _2bl_hdr.dwLength;
	AddStructures();
	SetupVariousFunctions();
	SetupRegSaves();
	LabelHeader();
	AddBLData(_2bl_hdr.wMagic);
}

void Load3bl(linput_t *_li)
{
	// TODO: What processor can read this? Xbox VM to init hardware
	//  move filestream to 3BL
	qlseek(_li, Get3blAddr());
	msg("3bl Header Magic: %X | Qfe: %X | Flags: %X | Entry: %08X | Size: %08X\n", _3bl_hdr.wMagic, _3bl_hdr.wQfe, _3bl_hdr.wFlags, _3bl_hdr.dwEntrypoint, _3bl_hdr.dwLength);
	BYTE* _3bl_buf = (BYTE*)malloc(_3bl_hdr.dwLength);
	// reset position
	qlseek(_li, Get3blAddr()); // start of 3bl
	lreadbytes(_li, _3bl_buf, _3bl_hdr.dwLength, false);
	// decrypt it
	XeCryptHmacSha(zeroKey, sizeof(blkey), &_3bl_buf[0x10], 0x10, NULL, 0, NULL, 0, _scKey, 0x10);
	XeCryptRc4(_scKey, 0x10, &_3bl_buf[0x20], _3bl_hdr.dwLength - 0x20);
	// add it to database
	mem2base(_3bl_buf, Get3blAddr(), _3bl_hdr.dwLength + Get3blAddr(), -1);
	set_selector(0, 0);
	add_segm(0, Get3blAddr(), _3bl_hdr.dwEntrypoint + Get3blAddr(), ".3bl_header", "DATA");
	add_segm(0, _3bl_hdr.dwEntrypoint + Get3blAddr(), _3bl_hdr.dwLength + Get3blAddr(), ".3bl_rom", "CODE");
	//add_segment_translation(_2bl_hdr.dwEntrypoint + hdr.dwEntrypoint, _2bl_hdr.dwEntrypoint + hdr.dwEntrypoint);
	//auto_make_proc(hdr.dwEntrypoint +_2bl_hdr.dwLength + _3bl_hdr.dwEntrypoint);
	total_size = _3bl_hdr.dwLength;
}

void Load4bl(linput_t *_li)
{
	SetupDatabaseCompilerInfo();
	set_processor_type("ppc", SETPROC_ALL | SETPROC_FATAL);
	// First we need to get our 3bl key so we can decrypt 4bl
	qlseek(_li, Get3blAddr() + 0x10);
	BYTE* _3bl_buf = (BYTE*)malloc(0x10);
	lreadbytes(_li, _3bl_buf, 0x10, false);
	// hash it
	XeCryptHmacSha(zeroKey, sizeof(blkey), _3bl_buf, 0x10, NULL, 0, NULL, 0, _scKey, 0x10);
	/*	4Bl Section		*/
	// reset position to 4bl
	qlseek(_li, Get4blAddr());
	msg("4bl Header Magic: %X | Qfe: %X | Flags: %X | Entry: %08X | Size: %08X\n", _4bl_hdr.wMagic, _4bl_hdr.wQfe, _4bl_hdr.wFlags, _4bl_hdr.dwEntrypoint, _4bl_hdr.dwLength);
	BYTE* _4bl_buf = (BYTE*)malloc(_4bl_hdr.dwLength);
	lreadbytes(_li, _4bl_buf, _4bl_hdr.dwLength, false);
	// decrypt it
	XeCryptHmacSha(_scKey, sizeof(blkey), &_4bl_buf[0x10], 0x10, NULL, 0, NULL, 0, _sdKey, 0x10);
	XeCryptRc4(_sdKey, 0x10, &_4bl_buf[0x20], _4bl_hdr.dwLength - 0x20);
	// add it to database
	mem2base(_4bl_buf, 0, _4bl_hdr.dwLength, -1);
	set_selector(0, 0);
	add_segm(0, 0, _4bl_hdr.dwEntrypoint, ".4bl_header", "DATA");
	add_segm(0, _4bl_hdr.dwEntrypoint, _4bl_hdr.dwLength, ".4bl_rom", "CODE");
	auto_make_proc(_4bl_hdr.dwEntrypoint);
	free(_3bl_buf);
	free(_4bl_buf);
	total_size = _4bl_hdr.dwLength;
	AddStructures();
	SetupVariousFunctions();
	SetupRegSaves();
	LabelHeader();
	AddBLData(_4bl_hdr.wMagic);
}

void Load5bl(linput_t *_li)
{
	//set_processor_type("ppc", SETPROC_ALL | SETPROC_FATAL);
	// First we need to get our 3bl key so we can decrypt 4bl
	qlseek(_li, Get3blAddr() + 0x10);
	BYTE* _3bl_buf = (BYTE*)malloc(0x10);
	lreadbytes(_li, _3bl_buf, 0x10, false);
	hexDump("3bl", &_3bl_buf[0x0], 0x10);
	// hash it
	XeCryptHmacSha(zeroKey, sizeof(blkey), _3bl_buf, 0x10, NULL, 0, NULL, 0, _scKey, 0x10);
	// Next get 4bl key so we can decrypt 5bl
	qlseek(_li, Get4blAddr() + 0x10);
	BYTE* _4bl_buf = (BYTE*)malloc(0x10);
	lreadbytes(_li, _4bl_buf, 0x10, false);
	hexDump("4bl", &_4bl_buf[0x0], 0x10);
	// hash it
	XeCryptHmacSha(_scKey, sizeof(blkey), _4bl_buf, 0x10, NULL, 0, NULL, 0, _sdKey, 0x10);
	// reset position to 5bl
	qlseek(_li, Get5blAddr());
	msg("5bl Header Magic: %X | Qfe: %X | Flags: %X | Entry: %08X | Size: %08X\n", _5bl_hdr.wMagic, _5bl_hdr.wQfe, _5bl_hdr.wFlags, _5bl_hdr.dwEntrypoint, _5bl_hdr.dwLength);
	BYTE* _5bl_buf = (BYTE*)malloc(_5bl_hdr.dwLength);
	lreadbytes(_li, _5bl_buf, _5bl_hdr.dwLength, false);
	// hash and decrypt it
	XeCryptHmacSha(_sdKey, sizeof(blkey), &_5bl_buf[0x10], 0x10, NULL, 0, NULL, 0, _seKey, 0x10);
	XeCryptRc4(_seKey, 0x10, &_5bl_buf[0x20], _5bl_hdr.dwLength - 0x20);
	hexDump("5bl", &_5bl_buf[0x0], 0x60);
	free(_3bl_buf);
	free(_4bl_buf);
	// add it to database
	//Entry = toEA(0, 0);
	/*ret = mem2base(_5bl_buf, Get5blAddr(), Get5blAddr() + _5bl_hdr.dwLength, -1);
	ret = set_selector(0, 0);
	ret = add_segm(0, Get5blAddr(), Get5blAddr() + _5bl_hdr.dwEntrypoint, ".5bl_header", "DATA");
	ret = add_segm(0, Get5blAddr() + _5bl_hdr.dwEntrypoint, Get5blAddr() + _5bl_hdr.dwLength, ".5bl_rom", "CODE");*/

	//LZX Decompression credit to 360 Flash Dump Tool Src
	tU2 U2;

	DWORD U1;
	unsigned char Ptr[0x8];
	tLDIC * pLDIC;

	unsigned int FileSize;	//,PatchSize;
							//	unsigned char PatchSHA[0x14];
	unsigned long Idx = 0, CSize, USize, Decomp;

	unsigned char * pBaseBuffer = (BYTE*)malloc(0x300000);
	unsigned char *pAt;


	memset(pBaseBuffer, 0, 0x300000);
	U1 = 0x800000;
	U2.U2 = 0x20000;
	U2.pUnknown = (void*)0x1103;
	LDICreateDecompression(&U1, &U2, Kmem_alloc, Kmem_free, Ptr, &pLDIC, NULL, NULL, NULL, NULL, NULL);

	pAt = &_5bl_buf[0x30];
	FileSize = _5bl_hdr.dwLength - 0x30;
	int pass = 0;

	while (FileSize)
	{
		// Get compressed block size
		EXTRACT_WORD(pAt, 0x00, CSize)
			pAt += 2;
		// Get decompressed block size
		EXTRACT_WORD(pAt, 0x00, USize)
			msg("CSize = %08X | USize = %08X\n", CSize, USize);
			pAt += 2;
		Decomp = USize;
		msg("LDIDecompress pass %i\n", pass);
		msg("FileSize: %08X | Idx: %08X\n", FileSize, Idx);
		void* r = LDIDecompress(pLDIC, pAt, CSize, &pBaseBuffer[Idx], &USize);
		msg("USize after = %08X\n", USize);
		if (Decomp != USize)
		{
			msg("failed LZX...Decomp = %08X : USize = %08X\n", Decomp, USize);
			break;
		}
		pAt += CSize;
		FileSize -= (0x04 + CSize);
		Idx += USize;
		pass++;
	}
	LDIDestroyDecompression(pLDIC);
	// Add HV to db
	/*mem2base(pBaseBuffer, 0, 0x40000, -1);
	add_segm(0, 0, 0x40000, ".hv", "CODE");
	auto_make_proc(Get5blAddr()+0x100);*/
	// Add decompressed 5bl to db
	msg("Adding decompressed 5bl: %08X : End = %08X\n",0, Idx);
	mem2base(&pBaseBuffer[0x40000],0, Idx, -1);
	add_segm(0, 0, Idx, ".5bl", "DATA");
	//free(pBaseBuffer);
	free(_5bl_buf);
	//FILE* _stream = fmemopen()
	//linput_t* _inp =  make_linput((FILE*)&pBaseBuffer[0x40000]);
	/*_li = (linput_t*)&pBaseBuffer[0x40000];
	BYTE* _3bl_buf2 = (BYTE*)malloc(0x10);
	lreadbytes(_li, _3bl_buf2, 0x10, false);
	hexDump("3bl", &_3bl_buf2[0x0], 0x10);*/
	int res = load_loader_module(_li, "pe", NULL, false);
	//msg("load_loader_module = %08X\n", res);
}

void HandleHeaders(linput_t *_li)
{
	if (askyn_c(1, "Found SB version: %d!\nWould you like to open it?", _2bl_hdr.wBuild) == 1)
		Load2bl(_li);
	else if (askyn_c(1, "Found SC version: %d!\nWould you like to open it?", _3bl_hdr.wBuild) == 1)
		Load3bl(_li);
	else if (askyn_c(1, "Found SD version: %d!\nWould you like to open it?", _4bl_hdr.wBuild) == 1)
		Load4bl(_li);
	else if (askyn_c(1, "Found SE version: %d!\nWould you like to open it?", _5bl_hdr.wBuild) == 1)
		Load5bl(_li);
}

void idaapi load_file(linput_t *_li, ushort /*neflag*/, const char * /*fileformatname*/) 
{
	msg("Inside: load_file\n");
	// First read ROM header
	lreadbytes(_li, &hdr.wMagic, 2, true);
	lreadbytes(_li, &hdr.wBuild, 2, true);
	lreadbytes(_li, &hdr.wQfe, 2, true);
	lreadbytes(_li, &hdr.wFlags, 2, true);
	lreadbytes(_li, &hdr.dwEntrypoint, 4, true);
	lreadbytes(_li, &hdr.dwLength, 4, true);
	// Read 2BL header
	qlseek(_li, Get2blAddr()); 
	lreadbytes(_li, &_2bl_hdr.wMagic, 2, true);
	lreadbytes(_li, &_2bl_hdr.wBuild, 2, true);
	lreadbytes(_li, &_2bl_hdr.wQfe, 2, true);
	lreadbytes(_li, &_2bl_hdr.wFlags, 2, true);
	lreadbytes(_li, &_2bl_hdr.dwEntrypoint, 4, true);
	lreadbytes(_li, &_2bl_hdr.dwLength, 4, true);
	//  Read 3BL header
	qlseek(_li, Get3blAddr());
	lreadbytes(_li, &_3bl_hdr.wMagic, 2, true);
	lreadbytes(_li, &_3bl_hdr.wBuild, 2, true);
	lreadbytes(_li, &_3bl_hdr.wQfe, 2, true);
	lreadbytes(_li, &_3bl_hdr.wFlags, 2, true);
	lreadbytes(_li, &_3bl_hdr.dwEntrypoint, 4, true);
	lreadbytes(_li, &_3bl_hdr.dwLength, 4, true);
	// Read 4BL header
	qlseek(_li, Get4blAddr());
	lreadbytes(_li, &_4bl_hdr.wMagic, 2, true);
	lreadbytes(_li, &_4bl_hdr.wBuild, 2, true);
	lreadbytes(_li, &_4bl_hdr.wQfe, 2, true);
	lreadbytes(_li, &_4bl_hdr.wFlags, 2, true);
	lreadbytes(_li, &_4bl_hdr.dwEntrypoint, 4, true);
	lreadbytes(_li, &_4bl_hdr.dwLength, 4, true);
	// Read 5BL header
	qlseek(_li, Get5blAddr());
	lreadbytes(_li, &_5bl_hdr.wMagic, 2, true);
	lreadbytes(_li, &_5bl_hdr.wBuild, 2, true);
	lreadbytes(_li, &_5bl_hdr.wQfe, 2, true);
	lreadbytes(_li, &_5bl_hdr.wFlags, 2, true);
	lreadbytes(_li, &_5bl_hdr.dwEntrypoint, 4, true);
	lreadbytes(_li, &_5bl_hdr.dwLength, 4, true);
	HandleHeaders(_li);
	//msg("Step 1.....\n");
	//// First step - read all data before 2BL into database
	//ret = file2base(_li, 0, 0, hdr.dwEntrypoint, FILEREG_PATCHABLE);
	//sel_t sel = segs.get_area_qty() + 1;
	//set_selector(sel, 0);
	//ea_t start = toEA(inf.baseaddr, 0);
	//ea_t end = start;
	//start = freechunk(end, hdr.dwEntrypoint, -0xF);
	//end = start + hdr.dwEntrypoint;
	//segment_t s;
	//s.sel = setup_selector(sel);
	//s.startEA = start;
	//s.endEA = end;
	//s.align = saRelByte;
	//s.comb = scPriv;
	//s.bitness = (uchar)ph.get_segm_bitness();
	//add_segm_ex(&s, "FlashHeader", "FlashHeader", ADDSEG_NOSREG | 0);
	//ret = set_selector(0, 0);
	//ret = add_segm(0, Entry, hdr.dwEntrypoint, "FlashHeader", "CONST");
	//
	msg("Done\n");
}

bool idaapi init_loader_options(linput_t*)
{
	//set_processor_type("ppc", SETPROC_ALL | SETPROC_FATAL);
	return true;
}

loader_t LDSC =
{
	IDP_INTERFACE_VERSION,
	0,                            // loader flags
								  //
								  //      check input file format. if recognized, then return 1
								  //      and fill 'fileformatname'.
								  //      otherwise return 0
								  //
								  accept_file,
								  //
								  //      load file into the database.
								  //
								  load_file,
								  //
								  //      create output file from the database.
								  //      this function may be absent.
								  //
								  NULL,
								  //      take care of a moved segment (fix up relocations, for example)
								  NULL,
								  //      initialize user configurable options based on the input file.
								  init_loader_options,
};