
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>

#include "bn/bn.h"
#include "bn/sha1.h"






#define iWAmarco_MALLOC_DEBUG_OPTION             1

typedef signed char        iWAint8;
typedef unsigned char    iWAuint8;
typedef signed short       iWAint16;
typedef unsigned short   iWAuint16;
typedef signed int          iWAint32;
typedef unsigned int       iWAuint32;
typedef unsigned int       iWAbool;


#define iWA_Std_malloc     malloc
#define iWA_Std_free        free
#define iWA_Std_memset   memset
#define iWA_Std_memcpy  memcpy
#define iWA_Std_strlen      strlen
#define iWA_Std_strcpy      strcpy
#define iWA_Std_strcmp      strcmp
#define iWA_Std_atoi          atoi 




extern void iWA_Log(const iWAint8 *pszFormat, ...);
extern void iWA_Dump(iWAuint8 *p, iWAint32 len);
extern iWAuint32 iWA_MemCount(void);
extern void iWA_Mprint(void);
extern void* iWA_Malloc(iWAuint32 size);
extern void iWA_Free(void* p);
extern void *iWA_Realloc(void *p, iWAuint32 size);      /*only match to mem.c of openssl, not be called really */

extern void iWA_Net_WritePacketUint16(iWAuint8 *packet, iWAuint16 data);
extern void iWA_Net_WritePacketUint32(iWAuint8 *packet, iWAuint32 data);
extern iWAuint16 iWA_Net_ReadPacketUint16(iWAuint8 *packet);
extern iWAuint32 iWA_Net_ReadPacketUint32(iWAuint8 *packet);
extern iWAuint32 iWA_Net_WritePacketBigNumber(iWAuint8 *packet, BIGNUM *bn);   /* return write byte num */
extern void iWA_Net_ReadPacketBigNumber(iWAuint8 *packet, iWAuint32 len, BIGNUM *bn);
extern iWAuint32 iWA_Net_ReadPacketAsciiString(iWAuint8 *packet, iWAuint8 *str_buf, iWAuint32 buf_size);  /* return packet read length, include tail '\0' */
extern void iWA_Auth_TestBn(void);


extern void iWA_Crypto_Sha1ResultBigNumber(SHA1Context *sha_ctx, BIGNUM *result);
extern void iWA_Crypto_Sha1Interleave(SHA1Context *sha_ctx, BIGNUM *result, BIGNUM *input);
extern void iWA_Crypto_Sha1InputBigNumber(SHA1Context *sha_ctx, BIGNUM *bn);
extern void iWA_Crypto_Sha1InputUint32(SHA1Context *sha_ctx, iWAuint32 i);
extern void iWA_Crypto_Sha1HashBigNumbers(SHA1Context *sha_ctx, BIGNUM *result, BIGNUM *bn0, ...);


extern void iWA_Auth_InitAuthInfoBlock(void);
extern void iWA_Auth_DeinitAuthInfoBlock(void);
extern void iWA_Auth_PrintAuthInfoBlock(void);
extern iWAuint32 iWA_Auth_WriteLogonChallengeClientPacket(void);   /* return : packet size */
extern iWAbool iWA_Auth_ReadLogonChallengeServerPacket(void);
extern iWAuint32 iWA_Auth_WriteLogonProofClientPacket(void);          /* return : packet size */
extern iWAbool iWA_Auth_ReadLogonProofBuild6005ServerPacket(void);
extern iWAuint32 iWA_Auth_WriteRealmListClientPacket(void);            /* return : packet size */
extern iWAbool iWA_Auth_ReadRealmListClientPacket(void);
extern iWAbool iWA_Auth_CalculateClientSrpValue(void);
extern iWAuint8* iWA_Auth_GetPacketBuf();
extern iWAuint32 iWA_Auth_GetClientBuild();
extern iWAuint8* iWA_Auth_GetUsername();
extern BIGNUM* iWA_Auth_GetK();


extern void iWA_World_InitSeesionInfoBlock(void);
extern void iWA_World_DeinitSeesionInfoBlock(void);
extern void iWA_World_PrintSessionInfoBlock(void);
extern void iWA_World_ReadWorldServerPacket(void);
extern iWAuint32 iWA_World_WriteCmsgAuthSessionPacket(void);
extern iWAuint32 iWA_World_WriteCmsgCharEnumPacket(void);
extern iWAuint8* iWA_World_GetPacketBuf(void);


