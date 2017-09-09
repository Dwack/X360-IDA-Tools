/************************************************
UGLY BODGERY to get at LDIC functions....
************************************************/
typedef struct 
{
	unsigned char * pLDICDataBuffer;
	DWORD			dw1;
	DWORD			MaxUSize;
}tLDICData;

typedef struct
{
	DWORD MagicNumber;
	void* pfn1;
	void* pfn2;
	void* pfn3;
	void* pfn4;
	void* pfn5;
	void* pfn6;
	void* pfn7;
	DWORD U1;
	DWORD U2;
	tLDICData * pLDICData;
}tLDIC;


typedef struct 
{
	DWORD U2;
	void* pUnknown;
}tU2;

extern "C"
{


HFDI FAR DIAMONDAPI LDICreateDecompression(
							  DWORD *  pUnk1,
							  tU2	*  pUnk2,
							  PFNALLOC pfnalloc,
                              PFNFREE  pfnfree,
							
							  void*    pPtr,					  
						      tLDIC **  pLDIC,

                              PFNOPEN  pfnopen,
                              PFNREAD  pfnread,
                              PFNWRITE pfnwrite,
                              PFNCLOSE pfnclose,
                              PFNSEEK  pfnseek);


HFDI FAR DIAMONDAPI LDIDecompress(
							  tLDIC* pLDIC, 
							  unsigned char * pdest_mem, 
							  unsigned int size_cur_uncompr_block, 
							  unsigned char * pinput, 
							  DWORD  * pUnk1);


HFDI FAR DIAMONDAPI LDIResetDecompression(
							  tLDIC* pLDIC);

HFDI FAR DIAMONDAPI LDIDestroyDecompression(
							  tLDIC* pLDIC);

int LZX_DecodeInsertDictionary(tLDICData * pLDICData, unsigned char* pOldAddress, unsigned long USize);

}