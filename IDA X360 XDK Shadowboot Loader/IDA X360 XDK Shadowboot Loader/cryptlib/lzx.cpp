#include "..\stdafx.h"
#include "..\cabio.h"
#include "fdi.h"
#include "lzx.h"



int LZX_DecodeInsertDictionary(tLDICData * pLDICData, unsigned char* pOldAddress, unsigned long USize)
{
	if(USize > pLDICData->MaxUSize)
	{
		return 0;
	}
	memset(pLDICData->pLDICDataBuffer,0,pLDICData->dw1);
	memcpy(&pLDICData->pLDICDataBuffer[pLDICData->dw1 - USize], pOldAddress, USize);
	return 1;
}
