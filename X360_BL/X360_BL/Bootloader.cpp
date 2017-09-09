
#include "Bootloader.h"

#define f_PPC 0x4252

Bootloader bl;

int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
	if ( n) return NULL;

	lreadbytes(li, &bl.Magic, 2, true);
	msg("Header: 0x%X\n", bl.Magic);
	if (bl.Magic != 0x4342 && bl.Magic != 0x4344 && bl.Magic != 0x4345 && bl.Magic != 0x4346 &&
		bl.Magic != 0x4347 && bl.Magic != 0x5342 && bl.Magic != 0x5343 && bl.Magic != 0x5344 &&
		bl.Magic != 0x5345 )
	{
		msg("Invalid Header...exiting\n");
		return NULL;
	}
	lreadbytes(li, &bl.Version, 2, true);
	lreadbytes(li, &bl.Qfe, 2, true);
	lreadbytes(li, &bl.Flags, 2, true);
	lreadbytes(li, &bl.Entry, 4, true);
	lreadbytes(li, &bl.Size, 4, true);
	msg("Header: %X | Qfe: %X| Flags: %X | Entry: %08X | Size: %08X\n", bl.Magic, bl.Qfe, bl.Flags, bl.Entry, bl.Size);
	qstrncpy(fileformatname, "X360 Bootloader", MAX_FILE_FORMAT_NAME);
	return 1;
}

void SetupRegSaves()
{
	msg("in REGISTER\n");
	char funcName[255];
	ea_t currAddr, i;
	for (currAddr = 0; currAddr != BADADDR; currAddr += 4)
	{
		currAddr = find_binary(currAddr, bl.Size, "F9 C1 FF 68 F9 E1 FF 70", 16, SEARCH_DOWN);
		if (currAddr == BADADDR) break;
		for (i = 14; i <= 31; i++)
		{
			if (i != 31) add_func(currAddr, currAddr + 4);
			else add_func(currAddr, currAddr + 0xC);
			sprintf(funcName, "__Save_R12_%d_thru_31", i);
			set_name(currAddr, funcName);
			currAddr +=4;
		}
	}

	for (currAddr = 0; currAddr != BADADDR; currAddr += 4)
	{
		currAddr = find_binary(currAddr, bl.Size, "E9 C1 FF 68 E9 E1 FF 70", 16, SEARCH_DOWN);
		if (currAddr == BADADDR) break;
		for (i = 14; i <= 31; i++)
		{
			if (i != 31) add_func(currAddr, currAddr + 4);
			else add_func(currAddr, currAddr + 0xC);
			sprintf(funcName, "__Rest_R12_lr_%d_thru_31", i);
			set_name(currAddr, funcName);
			currAddr +=4;
		}
	}
}

//Add per BL data
void AddBLData()
{
	// CB/SB
	if (bl.Magic == 0x5342 || bl.Magic == 0x4342)
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
	else if (bl.Magic == 0x5343)
	{
		doByte(0x20, 0x100);
		set_name(0x20, "pbSignature");
	}
	// SD/CD
	else if (bl.Magic == 0x5344 || bl.Magic == 0x4344)
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
	ea_t post = find_binary(0, bl.Size, "78 84 C1 C6 F8 83 00 00 4E 80 00 20", 16, SEARCH_DOWN);
	set_name(post, "BlpPOST_Out");
	apply_cdecl(post, "void BlpPOST_Out(_QWORD post_addr, _BYTE post_code);");
	post = find_binary(0, bl.Size, "38 00 00 00 7C 18 23 A6 4B FF FF F8 00 00 00 00", 16, SEARCH_DOWN);
	set_name(post, "BlpPanic");
	post = find_binary(0, bl.Size, "3D 40 67 45 3D 20 EF CD 3D 00 98 BA 3C E0 10 32", 16, SEARCH_DOWN);
	set_name(post, "XeCryptShaInit");
	apply_cdecl(post, "void XeCryptShaInit(XECRYPT_SHA_STATE * pShaState);");
	auto_make_proc(post);
	post = find_binary(0, bl.Size, "F8 21 FF 71 7C 7D 1B 78 7C BF 2B 78 7C 9E 23 78", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptShaUpdate");
	apply_cdecl(post - 8, "void XeCryptShaUpdate(XECRYPT_SHA_STATE * pShaState, const _BYTE * pbInp, _DWORD cbInp);");
	post = find_binary(0, bl.Size, "F8 61 FF F8 54 66 07 7E 28 06 00 00 20 C6 00 08", 16, SEARCH_DOWN);
	set_name(post, "memcpy");
	apply_cdecl(post, "void* memcmpy(void* ptrDest, void* ptrSrc, int num);");
	post = find_binary(NULL, bl.Size, "38 05 00 01 7C 09 03 A6 60 66 00 00 48 00 00 10 38 A5 FF FF", 16, SEARCH_DOWN);
	set_name(post, "memset");
	apply_cdecl(post, "void* memset(void* ptr, int value, int num);");
	post = find_binary(0, bl.Size, "F8 21 FE 21 7C 77 1B 78  7C 83 23 78 38 A0 00 10", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptShaTransform");
	apply_cdecl(post - 8, "void XeCryptShaTransform(_DWORD* pState, _BYTE * pbBuf);");
	post = find_binary(0, bl.Size, "28 05 00 00 7F 23 20 40 7C 83 20 50 7C A9 03 A6 4D C2 00 20 4D DA 00 20  80 C3 00 00 7C C3 21 2E 38 63 00 04 43 20 FF F4  4E 80 00 20", 16, SEARCH_DOWN);
	set_name(post, "XeCryptBnDw_Copy");
	post = find_binary(0, bl.Size, "F8 21 FF 61 7C 7F 1B 78 7C 99 23 78 3B DF 00 18", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptShaFinal");
	apply_cdecl(post - 8, "void XeCryptShaFinal(XECRYPT_SHA_STATE * pShaState, _BYTE * pbOut, _DWORD cbOut);");
	post = find_binary(0, bl.Size, "3C C0 00 01 3C E0 08 08 60 C6 02 03 60 E7 08 08", 16, SEARCH_DOWN);
	set_name(post, "XeCryptRc4Key");
	apply_cdecl(post, "void XeCryptRc4Key(XECRYPT_RC4_STATE * pRc4State, const _BYTE * pbKey, _DWORD cbKey);");
	post = find_binary(0, bl.Size, "28 05 00 00 4D C2 00 20 7C A9 03 A6 88 C3 01 00 88 E3 01 01", 16, SEARCH_DOWN);
	set_name(post, "XeCryptRc4Ecb");
	apply_cdecl(post, "void XeCryptRc4Ecb(XECRYPT_RC4_STATE * pRc4State, _BYTE * pbInpOut, _DWORD cbInpOut);");
	post = find_binary(NULL, bl.Size, "F8 21 FF 01 3D 60 67 45  7C 7F 1B 78 61 67 23 01", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptHmacShaInit");
	apply_cdecl(post - 8, "void XeCryptHmacShaInit(XECRYPT_HMACSHA_STATE * pHmacShaState, const _BYTE * pbKey, _DWORD cbKey);");
	post = find_binary(NULL, bl.Size, "F8 21 FE C1 7C BE 2B 78  7C 85 23 78 7C 64 1B 78", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptHmacSha");
	apply_cdecl(post - 8, "void XeCryptHmacSha(const _BYTE * pbKey, _DWORD cbKey, const _BYTE * pbInp1, _DWORD cbInp1, const _BYTE * pbInp2, _DWORD cbInp2, const _BYTE * pbInp3, _DWORD cbInp3, _BYTE * pbOut, _DWORD cbOut);");
	post = find_binary(NULL, bl.Size, "F8 21 FF 81 7C 9D 23 78  7C BC 2B 78 38 A0 00 00", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptHmacShaFinal");
	apply_cdecl(post - 8, "void XeCryptHmacShaFinal(XECRYPT_HMACSHA_STATE * pHmacShaState, _BYTE * pbOut, _DWORD cbOut);");
	post = find_binary(NULL, bl.Size, "F8 21 FF 01 39 60 00 00 7C 9E 23 78 7C 7F 1B 78", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptRotSumSha");
	apply_cdecl(post - 8, "void XeCryptRotSumSha(const _BYTE * pbInp1, _DWORD cbInp1, const _BYTE * pbInp2, _DWORD cbInp2, _BYTE * pbOut, _DWORD cbOut);");
	post = find_binary(0, bl.Size, "E8 E3 00 00 E9 23 00 08 E8 C3 00 10 E9 43 00 18", 16, SEARCH_DOWN);
	set_name(post, "XeCryptRotSum");
	//post = find_binary(0, bl.Size, "2B 1F 00 00 41 9A 00 14  7F E5 FB 78 7F C4 F3 78 38 61 00 50", 16, SEARCH_DOWN);
	//set_name(post, "XeCryptSha");
	// XeCryptSha(const BYTE * pbInp1, DWORD cbInp1, const BYTE * pbInp2, DWORD cbInp2, const BYTE * pbInp3, DWORD cbInp3, BYTE * pbOut, DWORD cbOut);
	// 2B 1F 00 00 41 9A 00 14  7F E5 FB 78 7F C4 F3 78 38 61 00 50
	post = find_binary(NULL, bl.Size, "F9 81 FF F8 FB E1 FF F0  F8 21 FF 71 39 60 00 14", 16, SEARCH_DOWN);
	set_name(post - 4, "XeCryptHmacShaVerify");
	apply_cdecl(post - 4, "bool XeCryptHmacShaVerify(const _BYTE * pbKey, _DWORD cbKey, const _BYTE * pbInp1, _DWORD cbInp1, const _BYTE * pbInp2, _DWORD cbInp2, const _BYTE * pbInp3, _DWORD cbInp3, const _BYTE * pbVer, _DWORD cbVer);");

	post = find_binary(0, bl.Size, "2C 05 00 00 7C A9 03 A6  38 E0 00 00 41 82 00 24 88 C4 00 00", 16, SEARCH_DOWN);
	set_name(post, "XeCryptMemDiff");
	apply_cdecl(post, "bool XeCryptMemDiff(const _BYTE * pbInp1, const _BYTE * pbInp2, _DWORD cbInp);");

	post = find_binary(0, bl.Size, "2C 05 00 00 7C A9 03 A6  38 E0 00 00 41 82 00 24 88 C4 00 00", 16, SEARCH_DOWN);
	set_name(post - 8, "XeCryptBnQwBeSigFormat");
	apply_cdecl(post - 8, "void XeCryptBnQwBeSigFormat(XECRYPT_SIG * pSig, const _BYTE * pbHash, const _BYTE * pbSalt);");

	// XeCryptBnQwNeModInv
	// 1D 63 00 03 69 6A 00 02  39 20 00 05 7D 6A 19 D2
	// 21 6B 00 01 39 0B 00 01  55 29 08 3C 7D 6B 59 D2
	post = find_binary(0, bl.Size, "1D 63 00 03 69 6A 00 02  39 20 00 05 7D 6A 19 D2", 16, SEARCH_DOWN);
	set_name(post, "XeCryptBnQwNeModInv");
	apply_cdecl(post, "_QWORD XeCryptBnQwNeModInv(_QWORD qw);");

	// XeCryptBnQwNeModMul - 40
	// 38 00 00 0B 7C 09 03 A6  38 00 00 00 39 C1 00 50

	// XeCryptBnQw_Copy
	// 28 05 00 00 7F 23 20 40  7C A9 03 A6 7C 83 20 50

	//XeCryptBnQwBeSigVerify(XECRYPT_SIG * pSig, const BYTE * pbHash, const BYTE * pbSalt, const XECRYPT_RSA * pRsa);

}

void idaapi load_file(linput_t *_li, ushort /*neflag*/, const char * /*fileformatname*/)
{
	int ret;
	bool aa;
	msg("Inside: load_file\n");
	lreadbytes(_li, &bl.Magic, 2, true);
	lreadbytes(_li, &bl.Version, 2, true);
	lreadbytes(_li, &bl.Qfe, 2, true);
	lreadbytes(_li, &bl.Flags, 2, true);
	lreadbytes(_li, &bl.Entry, 4, true);
	lreadbytes(_li, &bl.Size, 4, true);
	inf.baseaddr = 0;
	set_processor_type("ppc", SETPROC_ALL|SETPROC_FATAL);
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
	uint32 blEntry = toEA(X360_BL_BASEADDR, 0);
	ret = file2base(_li, 0, 0, bl.Size, FILEREG_PATCHABLE);
	ret = set_selector(1, 0);
	ret = add_segm(1, blEntry, bl.Size, "ROM", "ROM");
	ret = set_segm_addressing(getseg(blEntry), 1);
	auto_make_proc(bl.Entry);
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
	AddStructures();
	SetupVariousFunctions();
	SetupRegSaves();
	AddBLData();
	auto_make_proc(bl.Entry);
	msg("END\n");
	//ea_t post = find_binary(0, bl.Size, "78 84 C1 C6 F8 83 00 00 4E 80 00 20", 16, SEARCH_DOWN);
	//msg("start %X\n",post);
	//xrefblk_t xb;
	//xb.first_from(0xB80, XREF_ALL);
 //   /*for ( bool ok=xb.first_from(post, XREF_ALL); ok; ok=xb.next_from() )
 //   {*/
 //       msg("%X\n", xb.to);// - contains the referenced address
	//	xb.first_to(post, XREF_ALL);
	//	msg("%X\n", xb.from);
	//	msg("%X\n", get_first_fcref_to(post));
 //   //}
}

bool idaapi init_loader_options(linput_t*)
{
  set_processor_type("ppc", SETPROC_ALL|SETPROC_FATAL);
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