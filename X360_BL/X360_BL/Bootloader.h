
#include "idaldr.h"
#include "search.hpp"
#include "typeinf.hpp"
#include "struct.hpp"

#define X360_BL_BASEADDR 0


typedef struct _BOOTLOADER_
{
	ushort		Magic;
	ushort		Version;
	ushort		Qfe;
	ushort		Flags;
	uint32		Entry;
	uint32		Size;
} Bootloader, *pBootloader;