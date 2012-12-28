
#ifndef __iWA_H__
#define __iWA_H__

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>

#include <pthread.h>
#include <semaphore.h>

#include "bn/bn.h"
#include "bn/sha1.h"

//#define _iWA_CLIENT_              1
#define _SERVER_IP_    "127.0.0.1"
//#define _SERVER_IP_    "192.168.10.107"
//#define _SERVER_IP_    "192.168.1.6" 



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


enum
{
    iWAenum_AUTH_MSG_AUTH_OK                                         = 0x00,
    iWAenum_AUTH_MSG_AUTH_CONNECT_ERROR                   = 0x01,
    iWAenum_AUTH_MSG_AUTH_INVALID_USERNAME                = 0x02,
    iWAenum_AUTH_MSG_AUTH_INVALID_PASSWORD              = 0x03,
    iWAenum_AUTH_MSG_AUTH_SERVER_LIST                         = 0x04,

    iWAenum_AUTH_MSG_REG_OK                                          = 0x10,
    iWAenum_AUTH_MSG_REG_CONNECT_ERROR                     = 0x11,    
    iWAenum_AUTH_MSG_REG_USERNAME_EXIST                    = 0x12,    
    iWAenum_AUTH_MSG_REG_CREATE_FAIL                           = 0x13,        
};

enum
{
    iWAenum_AUTH_SERVER_STATUS_NEW,
    iWAenum_AUTH_SERVER_STATUS_HOT,
    iWAenum_AUTH_SERVER_STATUS_MAINTAIN,
};

#define iWAmacro_AUTH_SERVER_NAME_SIZE          (32)
#define iWAmacro_AUTH_SERVER_ADDRESS_SIZE    (20)
#define iWAmacro_AUTH_SERVER_HIT_SIZE             (32)

#define iWAmacro_WORLD_CHARACTER_NAME_SIZE     (32)
#define iWAmacro_WORLD_CHARACTER_RACE_SIZE     (20)
#define iWAmacro_WORLD_CHARACTER_NATION_SIZE   (20)

typedef struct
{
    iWAuint8     region;
    iWAuint8     status;
    iWAuint8     name[iWAmacro_AUTH_SERVER_NAME_SIZE];
    iWAuint8     hit[iWAmacro_AUTH_SERVER_HIT_SIZE];
    iWAuint8     address[iWAmacro_AUTH_SERVER_ADDRESS_SIZE];
    iWAuint16   port;
    iWAuint16   character_num;
    iWAuint16   character_class;    
    iWAuint8     character_name[iWAmacro_WORLD_CHARACTER_NAME_SIZE];
    iWAuint8     character_race[iWAmacro_WORLD_CHARACTER_RACE_SIZE];
    iWAuint8     character_nation[iWAmacro_WORLD_CHARACTER_NATION_SIZE];
}iWAstruct_Auth_Server;


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


extern void iWA_Auth_Init(void);
extern void iWA_Auth_Deinit(void);
extern iWAuint32 iWA_Auth_GetClientBuild(void);
extern iWAuint8* iWA_Auth_GetUsername(void);
extern BIGNUM* iWA_Auth_GetK(void);
extern void iWA_Auth_DoReceive(void);
extern iWAbool iWA_Auth_DoAuth(iWAuint8 *server, iWAuint16 port, iWAuint8 *username, iWAuint8 *password, void *msg_cb);
extern iWAbool iWA_Auth_DoReg(iWAuint8 *server, iWAuint16 port, iWAuint8 *username, iWAuint8 *password, void *msg_cb);

extern void iWA_World_InitSessionInfoBlock(void);
extern void iWA_World_DeinitSessionInfoBlock(void);
extern void iWA_World_PrintSessionInfoBlock(void);
//extern void iWA_World_ReadWorldServerPacket(void);
extern iWAuint32 iWA_World_WriteCmsgAuthSessionPacket(void);
extern iWAuint32 iWA_World_WriteCmsgCharEnumPacket(void);
extern iWAuint32 iWA_World_WriteCmsgPlayerLoginPacket(void);
//extern iWAuint8* iWA_World_GetPacketBuf(void);
extern void iWA_World_SendPacket(void);
extern void iWA_World_ReceivePacket(void);


extern iWAbool iWA_Socket_InitSession(iWAuint8 *ip, iWAuint16 port, iWAuint32 send_buf_size, iWAuint32 recv_buf_size, void *func_split, iWAuint32 split_size, void *func_decrypt);
extern void iWA_Socket_DeinitSession(void);
extern iWAbool iWA_Socket_SendPacket(iWAuint8 *data, iWAuint32 len);
extern iWAbool iWA_Socket_ReceivePacket(iWAuint8 *data, iWAuint32 *len);
extern iWAbool iWA_Socket_ReceivePacket2(iWAuint8 **data, iWAuint32 *len, iWAuint32 **valid);


#endif         /* __iWA_H__ */

