


#include "iWA.h"






typedef struct 
{
    iWAuint8   cmd;                //iWAenum_AUTH_CMD_AUTH_LOGON_CHALLENGE
    iWAuint8   error;
    iWAuint8   size[2];            //Size of the remaining part of the message
    iWAuint8   gamename[4];    //4 byte C-String, containing the String "WoW\0"
    iWAuint8   version1;            //Major version number of the client ( 1 for 1.12.1 )
    iWAuint8   version2;            //Minor version number of the client ( 12 for 1.12.1 )
    iWAuint8   version3;            //Patchlevel version number of the client ( 1 for 1.12.1 )
    iWAuint8   build[2];            //Build number of the client. ( 5875 for 1.12.1 )
    iWAuint8   platform[4];        //Platform the client is running on, reversed C-String ( "68x\0" for x86 )
    iWAuint8   os[4];            //OS the client is running on, reversed C-String ( "niW\0" for Windows )
    iWAuint8   country[4];        //Locale of the client, reversed C-String ( "SUne" for enUS )
    iWAuint8   timezone_bias[4];
    iWAuint8   ip[4];                //IP address of the client in binary format
    iWAuint8   username_len;            //Length of the Identity ( user name ) in characters
    iWAuint8   username[1];                //The Identity string ( user name )
}iWAstruct_Auth_LogonChallengeClientPacket;


typedef struct
{
    iWAuint8   cmd;            //iWAenum_AUTH_CMD_AUTH_LOGON_CHALLENGE
    iWAuint8   zero;            // always 0x00
    iWAuint8   error;         //result code
    iWAuint8   B[32];        //B is an SRP6 value. It is the server's public value.
    iWAuint8   g_len;        //Length of the SRP6 g value we send the client in bytes. Always 1
    iWAuint8   g[1];            //The SRP6 g value we send the client. Always 7
    iWAuint8   N_len;        //Lenght of the SRP6 N value we send the client. Always 32
    iWAuint8   N[32];        //The SRP6 N value we send the client. 
    iWAuint8   s[32];        //The SRP6 s value
    iWAuint8   unk3[16];        //a randomly generated 16 byte value.
    iWAuint8   unk4;        //a single byte 0.
}iWAstruct_Auth_LogonChallengeServerPacket;


typedef struct
{
    iWAuint8   cmd;                    //iWAenum_AUTH_CMD_AUTH_LOGON_PROOF
    iWAuint8   A[32];                //The client SRP6 A value ( public client value ).
    iWAuint8   M1[20];                //The client's SRP6 M value.待比较的最终值
    iWAuint8   crc_hash[20];            //doesn't seem to be used
    iWAuint8   number_of_keys;        //It also seems to be always 0
    iWAuint8   securityFlags;                 // 0x00-0x04
}iWAstruct_Auth_LogonProofClientPacket;


typedef struct
{
    iWAuint8   cmd;                /* iWAenum_AUTH_CMD_AUTH_LOGON_PROOF */
    iWAuint8   error;
    iWAuint8   M2[20];
    iWAuint8   unk2[4];
} iWAstruct_Auth_LogonProofBuild6005ServerPacket;

typedef struct
{
    iWAuint8   cmd;                    /*  iWAenum_AUTH_CMD_REALM_LIST */
    iWAuint8   unk[4];         
}iWAstruct_Auth_RealmListClientPacket;

typedef struct
{
    iWAuint8 cmd;                    /*  iWAenum_AUTH_CMD_REALM_LIST */
    iWAuint8 pkt_size[2];       
    iWAuint8 unk[4];            
    iWAuint8 realm_list_size;
    iWAuint8 realms[1];
}iWAstruct_Auth_RealmListServerPacketHeader;






enum
{
    iWAenum_AUTH_CMD_AUTH_LOGON_CHALLENGE        = 0x00,
    iWAenum_AUTH_CMD_AUTH_LOGON_PROOF            = 0x01,
    iWAenum_AUTH_CMD_AUTH_RECONNECT_CHALLENGE    = 0x02,
    iWAenum_AUTH_CMD_AUTH_RECONNECT_PROOF        = 0x03,
    iWAenum_AUTH_CMD_REALM_LIST                  = 0x10,
    iWAenum_AUTH_CMD_XFER_INITIATE               = 0x30,
    iWAenum_AUTH_CMD_XFER_DATA                   = 0x31,
    // these opcodes no longer exist in currently supported client
    iWAenum_AUTH_CMD_XFER_ACCEPT                 = 0x32,
    iWAenum_AUTH_CMD_XFER_RESUME                 = 0x33,
    iWAenum_AUTH_CMD_XFER_CANCEL                 = 0x34
};

enum
{
    iWAenum_AUTH_RESULT_SUCCESS                     = 0x00,
    iWAenum_AUTH_RESULT_FAIL_UNKNOWN0               = 0x01,                 ///< ? Unable to connect
    iWAenum_AUTH_RESULT_FAIL_UNKNOWN1               = 0x02,                 ///< ? Unable to connect
    iWAenum_AUTH_RESULT_FAIL_BANNED                 = 0x03,                 ///< This <game> account has been closed and is no longer available for use. Please go to <site>/banned.html for further information.
    iWAenum_AUTH_RESULT_FAIL_UNKNOWN_ACCOUNT        = 0x04,                 ///< The information you have entered is not valid. Please check the spelling of the account name and password. If you need help in retrieving a lost or stolen password, see <site> for more information
    iWAenum_AUTH_RESULT_FAIL_INCORRECT_PASSWORD     = 0x05,                 ///< The information you have entered is not valid. Please check the spelling of the account name and password. If you need help in retrieving a lost or stolen password, see <site> for more information
    // client reject next login attempts after this error, so in code used iWAenum_AUTH_RESULT_FAIL_UNKNOWN_ACCOUNT for both cases
    iWAenum_AUTH_RESULT_FAIL_ALREADY_ONLINE         = 0x06,                 ///< This account is already logged into <game>. Please check the spelling and try again.
    iWAenum_AUTH_RESULT_FAIL_NO_TIME                = 0x07,                 ///< You have used up your prepaid time for this account. Please purchase more to continue playing
    iWAenum_AUTH_RESULT_FAIL_DB_BUSY                = 0x08,                 ///< Could not log in to <game> at this time. Please try again later.
    iWAenum_AUTH_RESULT_FAIL_VERSION_INVALID        = 0x09,                 ///< Unable to validate game version. This may be caused by file corruption or interference of another program. Please visit <site> for more information and possible solutions to this issue.
    iWAenum_AUTH_RESULT_FAIL_VERSION_UPDATE         = 0x0A,                 ///< Downloading
    iWAenum_AUTH_RESULT_FAIL_INVALID_SERVER         = 0x0B,                 ///< Unable to connect
    iWAenum_AUTH_RESULT_FAIL_SUSPENDED              = 0x0C,                 ///< This <game> account has been temporarily suspended. Please go to <site>/banned.html for further information
    iWAenum_AUTH_RESULT_FAIL_FAIL_NOACCESS          = 0x0D,                 ///< Unable to connect
    iWAenum_AUTH_RESULT_SUCCESS_SURVEY              = 0x0E,                 ///< Connected.
    iWAenum_AUTH_RESULT_FAIL_PARENTCONTROL          = 0x0F,                 ///< Access to this account has been blocked by parental controls. Your settings may be changed in your account preferences at <site>
    iWAenum_AUTH_RESULT_FAIL_LOCKED_ENFORCED        = 0x10,                 ///< You have applied a lock to your account. You can change your locked status by calling your account lock phone number.
    iWAenum_AUTH_RESULT_FAIL_TRIAL_ENDED            = 0x11,                 ///< Your trial subscription has expired. Please visit <site> to upgrade your account.
    iWAenum_AUTH_RESULT_FAIL_USE_BATTLENET          = 0x12,                 ///< iWAenum_AUTH_RESULT_FAIL_OTHER This account is now attached to a Battle.net account. Please login with your Battle.net account email address and password.
};


#define iWAmacro_AUTH_INFO_REALM_NAME_MAXIUM          (32)
#define iWAmacro_AUTH_INFO_REALM_ADDRESS_MAXIUM    (32)


typedef struct
{
    iWAuint32   type;    
    iWAuint32   population;
    iWAuint16   port;    
    iWAuint8    name[iWAmacro_AUTH_INFO_REALM_NAME_MAXIUM];
    iWAuint8    address[iWAmacro_AUTH_INFO_REALM_ADDRESS_MAXIUM];
    iWAuint8    flag;  
    iWAuint8    characters;
    iWAuint8    timezone;  
}iWAstruct_Auth_RealmList;


#define iWAmacro_AUTH_INFO_USERNAME_MAXIUM             (64)
#define iWAmacro_AUTH_INFO_PASSWORD_MAXIUM            (64)
#define iWAmacro_AUTH_INFO_PACKET_MAXIUM                  (1024)
#define iWAmacro_AUTH_INFO_REALM_MAXIUM                   (16)


typedef struct
{
    iWAuint16 valid;        /* Auth session valid */
    iWAuint16 client_build;
    iWAuint8 username[iWAmacro_AUTH_INFO_USERNAME_MAXIUM];
    iWAuint8 password[iWAmacro_AUTH_INFO_PASSWORD_MAXIUM];
    iWAuint8 packet[iWAmacro_AUTH_INFO_PACKET_MAXIUM];    
    iWAuint32 packet_len;
    BIGNUM B, g, N, s, M2;  /* received from server */
    BIGNUM a, A, S, K, M1;  /* generate at client */
    iWAuint16 realms_num;   
    iWAstruct_Auth_RealmList realms[iWAmacro_AUTH_INFO_REALM_MAXIUM];
}iWAstruct_Auth_AuthInfoBlock;


static iWAstruct_Auth_AuthInfoBlock auth_info_block = {0};



static iWAuint32 split_auth_packet(iWAuint8 *pkt, iWAuint32 len)
{
    iWAuint32 size;

    switch(pkt[0])
    {
        case iWAenum_AUTH_CMD_AUTH_LOGON_CHALLENGE:
            size = sizeof(iWAstruct_Auth_LogonChallengeServerPacket);
            break;
        case iWAenum_AUTH_CMD_AUTH_LOGON_PROOF:
            size = sizeof(iWAstruct_Auth_LogonProofBuild6005ServerPacket);
            break;
        case iWAenum_AUTH_CMD_REALM_LIST:
            size = iWA_Net_ReadPacketUint16(pkt+1) + 3;
            break;
        default:
            size = 0;
    }

    return size;
}


void iWA_Auth_InitAuthInfoBlock(void)
{
    iWA_Log("iWA_Auth_InitAuthInfoBlock()");

    iWA_Std_memset((void*)&auth_info_block, 0, sizeof(iWAstruct_Auth_AuthInfoBlock));

    BN_init(&auth_info_block.B);
    BN_init(&auth_info_block.g);
    BN_init(&auth_info_block.N);
    BN_init(&auth_info_block.s);
    BN_init(&auth_info_block.M2);
    BN_init(&auth_info_block.a);
    BN_init(&auth_info_block.A);
    BN_init(&auth_info_block.S);
    BN_init(&auth_info_block.K);
    BN_init(&auth_info_block.M1);

    auth_info_block.client_build = 5875;
    iWA_Std_strcpy(auth_info_block.username, "LOUHAO");
    iWA_Std_strcpy(auth_info_block.password, "LOUHAO");

    auth_info_block.valid = 1;

#define _SERVER_IP_    "127.0.0.1"
//#define _SERVER_IP_    "192.168.10.105"
//#define _SERVER_IP_    "192.168.1.6" 


    iWA_Socket_InitSession(_SERVER_IP_, 3724, 1024, 1024, (void*)split_auth_packet, 3, NULL);
}

void iWA_Auth_DeinitAuthInfoBlock()
{
    iWA_Log("iWA_Auth_DeinitAuthInfoBlock()");

    auth_info_block.valid = 0;

    BN_free(&auth_info_block.B);
    BN_free(&auth_info_block.g);
    BN_free(&auth_info_block.N);
    BN_free(&auth_info_block.s);
    BN_free(&auth_info_block.M2);
    BN_free(&auth_info_block.a);
    BN_free(&auth_info_block.A);
    BN_free(&auth_info_block.S);
    BN_free(&auth_info_block.K);
    BN_free(&auth_info_block.M1);
}

void iWA_Auth_SendPacket(void)
{
    iWA_Log("iWA_Auth_SendPacket()");

    if(!auth_info_block.valid)     return;

    iWA_Socket_SendPacket(auth_info_block.packet, auth_info_block.packet_len);    
}

void iWA_Auth_ReceivePacket(void)
{
    //iWA_Log("iWA_Auth_ReceivePacket()");

    if(!auth_info_block.valid)     return;

    if(iWA_Socket_ReceivePacket(auth_info_block.packet, &auth_info_block.packet_len))
    {
        iWA_Log("iWA_Auth_ReceivePacket() get new packet");
    
        switch(auth_info_block.packet[0])
        {
            case iWAenum_AUTH_CMD_AUTH_LOGON_CHALLENGE:
                if(iWA_Auth_ReadLogonChallengeServerPacket())
                {
                    iWA_Auth_CalculateClientSrpValue();
                    iWA_Auth_WriteLogonProofClientPacket();
                    iWA_Auth_SendPacket();
                }    
                break;
            case iWAenum_AUTH_CMD_AUTH_LOGON_PROOF:
                if(iWA_Auth_ReadLogonProofBuild6005ServerPacket())
                {
                    iWA_Auth_WriteRealmListClientPacket();
                    iWA_Auth_SendPacket();
                }
                break;
            case iWAenum_AUTH_CMD_REALM_LIST:
                iWA_Auth_ReadRealmListClientPacket();
                iWA_Auth_PrintAuthInfoBlock();
                //iWA_Auth_DeinitAuthInfoBlock();

                auth_info_block.valid = 0;
                iWA_Socket_DeinitSession();
                iWA_World_InitSessionInfoBlock();
                break;        
        }
    }
}

void iWA_Auth_PrintAuthInfoBlock()
{
    iWAuint16 i;
    iWAstruct_Auth_RealmList *realm;

    iWA_Log("iWA_Auth_PrintAuthInfoBlock()");

    iWA_Log("username : %s", auth_info_block.username);    
    iWA_Log("password : %s", auth_info_block.password);    

    iWA_Log("B : %s", BN_bn2hex(&auth_info_block.B));
    iWA_Log("g : %s", BN_bn2hex(&auth_info_block.g));
    iWA_Log("N : %s", BN_bn2hex(&auth_info_block.N));    
    iWA_Log("s : %s", BN_bn2hex(&auth_info_block.s));
    iWA_Log("M2 : %s", BN_bn2hex(&auth_info_block.M2));    
    iWA_Log("a : %s", BN_bn2hex(&auth_info_block.a));
    iWA_Log("A : %s", BN_bn2hex(&auth_info_block.A));    
    iWA_Log("S : %s", BN_bn2hex(&auth_info_block.S));
    iWA_Log("K : %s", BN_bn2hex(&auth_info_block.K));
    iWA_Log("M1 : %s", BN_bn2hex(&auth_info_block.M1)); 

    iWA_Log("realms_num : %d", auth_info_block.realms_num);

    for(i = 0; i < auth_info_block.realms_num; i++)
    {
        realm = &auth_info_block.realms[i];
        iWA_Log("[realm %d] name:%s, address:%s, port:%d", i+1, realm->name, realm->address, realm->port);
    }
}



/* return : packet size */
iWAuint32 iWA_Auth_WriteLogonChallengeClientPacket()
{
    iWAstruct_Auth_LogonChallengeClientPacket *packet;
    iWAuint32 username_len;
    iWAuint16 packet_size;

    iWA_Log("iWA_Auth_WriteLogonChallengeClientPacket()");


    username_len = iWA_Std_strlen(auth_info_block.username);
    if(username_len == 0)     return 0;

    packet = (iWAstruct_Auth_LogonChallengeClientPacket*)auth_info_block.packet;

    iWA_Std_memset((void*)packet, 0, sizeof(iWAstruct_Auth_LogonChallengeClientPacket));

    packet->cmd = iWAenum_AUTH_CMD_AUTH_LOGON_CHALLENGE;
    packet->error = 0x00;
    packet_size = &(packet->username[0]) - &(packet->gamename[0]) + username_len;
    iWA_Net_WritePacketUint16(packet->size, packet_size);
    
    iWA_Std_memcpy((void*)packet->gamename, "WoW", 3);
    
    packet->version1 = 1;
    packet->version2 = 12;
    packet->version3 = 1;
    iWA_Net_WritePacketUint16(packet->build, auth_info_block.client_build);

    iWA_Std_memcpy((void*)packet->platform, "68x", 3);
    iWA_Std_memcpy((void*)packet->os, "niW", 3);
    iWA_Std_memcpy((void*)packet->country, "SUne", 4);

    packet->ip[0] = 127;
    packet->ip[1] = 0;
    packet->ip[2] = 0;
    packet->ip[3] = 1;    
    
    packet->username_len = username_len;
    
    iWA_Std_strcpy(packet->username, auth_info_block.username);

    auth_info_block.packet_len = packet_size + 4;

    return (packet_size + 4);
}


iWAbool iWA_Auth_ReadLogonChallengeServerPacket()
{
    iWAstruct_Auth_LogonChallengeServerPacket *packet;

    iWA_Log("iWA_Auth_ReadLogonChallengeServerPacket()");

    packet = (iWAstruct_Auth_LogonChallengeServerPacket*)auth_info_block.packet;

    if(packet->cmd != iWAenum_AUTH_CMD_AUTH_LOGON_CHALLENGE)     return 0;

    if(packet->error != iWAenum_AUTH_RESULT_SUCCESS)   return 0;

    iWA_Net_ReadPacketBigNumber(packet->B, 32, &(auth_info_block.B)); 
    iWA_Net_ReadPacketBigNumber(packet->g, packet->g_len, &(auth_info_block.g)); 
    iWA_Net_ReadPacketBigNumber(packet->N, packet->N_len, &(auth_info_block.N)); 
    iWA_Net_ReadPacketBigNumber(packet->s, 32, &(auth_info_block.s)); 
    
    return 1;
}

/* return : packet size */
iWAuint32 iWA_Auth_WriteLogonProofClientPacket()
{
    iWAstruct_Auth_LogonProofClientPacket *packet;

    iWA_Log("iWA_Auth_WriteLogonProofClientPacket()");

    packet = (iWAstruct_Auth_LogonProofClientPacket*)auth_info_block.packet;

    iWA_Std_memset((void*)packet, 0, sizeof(iWAstruct_Auth_LogonProofClientPacket));

    packet->cmd = iWAenum_AUTH_CMD_AUTH_LOGON_PROOF;

    iWA_Net_WritePacketBigNumber(packet->A, &(auth_info_block.A));
    iWA_Net_WritePacketBigNumber(packet->M1, &(auth_info_block.M1));    

    auth_info_block.packet_len = sizeof(iWAstruct_Auth_LogonProofClientPacket);

    return sizeof(iWAstruct_Auth_LogonProofClientPacket);
}

iWAbool iWA_Auth_ReadLogonProofBuild6005ServerPacket()
{
    iWAstruct_Auth_LogonProofBuild6005ServerPacket *packet;

    iWA_Log("iWA_Auth_ReadLogonProofBuild6005ServerPacket()");

    packet = (iWAstruct_Auth_LogonProofBuild6005ServerPacket*)auth_info_block.packet;

    if(packet->cmd != iWAenum_AUTH_CMD_AUTH_LOGON_PROOF)     return 0;

    if(packet->error != iWAenum_AUTH_RESULT_SUCCESS)   return 0;   

    iWA_Net_ReadPacketBigNumber(packet->M2, 20, &(auth_info_block.M2)); 

    return 1;
}

/* return : packet size */
iWAuint32 iWA_Auth_WriteRealmListClientPacket()
{
    iWAstruct_Auth_RealmListClientPacket *packet;

    iWA_Log("iWA_Auth_WriteRealmListClientPacket()");

    packet = (iWAstruct_Auth_RealmListClientPacket*)auth_info_block.packet;

    iWA_Std_memset((void*)packet, 0, sizeof(iWAstruct_Auth_RealmListClientPacket));

    packet->cmd = iWAenum_AUTH_CMD_REALM_LIST;

    auth_info_block.packet_len = sizeof(iWAstruct_Auth_RealmListClientPacket);
    
    return sizeof(iWAstruct_Auth_RealmListClientPacket);
}

iWAbool iWA_Auth_ReadRealmListClientPacket()
{
    iWAstruct_Auth_RealmListServerPacketHeader *packet;
    iWAstruct_Auth_RealmList *realm;
    iWAuint8 *p, *c;
    iWAuint16 i;

    iWA_Log("iWA_Auth_ReadRealmListClientPacket()");

    packet = (iWAstruct_Auth_RealmListServerPacketHeader*)auth_info_block.packet;

    if(packet->cmd != iWAenum_AUTH_CMD_REALM_LIST)     return 0;

    auth_info_block.realms_num = (iWAuint16)packet->realm_list_size;

    p = packet->realms;
    for(i = 0; i < auth_info_block.realms_num; i++)
    {
        realm = &auth_info_block.realms[i];
        iWA_Std_memset((void*)realm, 0, sizeof(iWAstruct_Auth_RealmList));

        /* fill iWAstruct_Auth_RealmList */
        realm->type = iWA_Net_ReadPacketUint32(p);
        p += 4;

        realm->flag = *p++;

        p += iWA_Net_ReadPacketAsciiString(p, realm->name, iWAmacro_AUTH_INFO_REALM_NAME_MAXIUM);
        p += iWA_Net_ReadPacketAsciiString(p, realm->address, iWAmacro_AUTH_INFO_REALM_ADDRESS_MAXIUM);

        realm->population = iWA_Net_ReadPacketUint32(p);
        p += 4;

        realm->characters = *p++;
        realm->timezone = *p++;

        /* parse port from address */
        c = realm->address;
        while(*c != 0x00)
        {
            if(*c == ':')
            {
                *c = 0x00;
                realm->port = iWA_Std_atoi(c+1);
                break;
            }
            
            c++;
        }
    }
    

    return 1;

}

iWAbool iWA_Auth_CalculateClientSrpValue()
{
    iWAbool ret = 0;
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *I = BN_new(), *p = BN_new(), *u = BN_new(), *x = BN_new();
    BIGNUM *S1 = BN_new(), *S2 = BN_new(), *S3 = BN_new(), *k =  BN_new();
    SHA1Context *sha_ctx = (SHA1Context*)iWA_Malloc(sizeof(SHA1Context));
    iWAuint32 i;

    iWA_Log("iWA_Auth_CalculateClientSrpValue()");

    if(sha_ctx == NULL || bn_ctx == NULL || I == NULL || p == NULL || u == NULL || x == NULL)   goto end;
    if(S1 == NULL || S2 == NULL || S3 == NULL)   goto end;

    /* a = random 32 byte */
     //BN_bntest_rand(&auth_info_block.a, 32*8, 0, 1);
     BN_rand(&auth_info_block.a, 32*8, 0, 1);
#if 0
    {
        BIGNUM *tmp = &auth_info_block.a;
        BN_hex2bn(&tmp, "B4E8899F9A31CC8B000178D990F241E826EF4A441A9072E9EE178FE7F7C6F257");
    }
#endif

    /* A = g^a % N */
    BN_mod_exp(&auth_info_block.A, &auth_info_block.g, &auth_info_block.a, &auth_info_block.N, bn_ctx);

    /* I = H(username)  */
    SHA1Reset(sha_ctx);
    SHA1Input(sha_ctx, auth_info_block.username, iWA_Std_strlen(auth_info_block.username));  
    iWA_Crypto_Sha1ResultBigNumber(sha_ctx, I);

    /* p = H(username:password) */
    SHA1Reset(sha_ctx);
    SHA1Input(sha_ctx, auth_info_block.username, iWA_Std_strlen(auth_info_block.username));
    SHA1Input(sha_ctx, ":", 1);
    SHA1Input(sha_ctx, auth_info_block.password, iWA_Std_strlen(auth_info_block.password));    
    iWA_Crypto_Sha1ResultBigNumber(sha_ctx, p);

    /* u = H(A, B) */
    iWA_Crypto_Sha1HashBigNumbers(sha_ctx, u, &auth_info_block.A, &auth_info_block.B, NULL);

    /* x = H(s, p) */
    iWA_Crypto_Sha1HashBigNumbers(sha_ctx, x, &auth_info_block.s, p, NULL);

    /* S = (B - k*(g^x%N)) ^ (a + u*x) % N */
    /* S1 = g ^ x % N */
    BN_mod_exp(S1, &auth_info_block.g, x, &auth_info_block.N, bn_ctx);

    /* S2 = S1 * k */
    BN_hex2bn(&k, "3");
    BN_mul(S2, S1, k, bn_ctx);

    /* S3 = B - S2 */
    BN_sub(S3, &auth_info_block.B, S2);

    /* S1 = u * x */
    BN_mul(S1, u, x, bn_ctx);

    /* S2 = a + S1 */
    BN_add(S2, &auth_info_block.a, S1);

    /* S = S3 ^ S2 % N */
    BN_mod_exp(&auth_info_block.S, S3, S2, &auth_info_block.N, bn_ctx);

    /* K = H_interleave(S) */
    iWA_Crypto_Sha1Interleave(sha_ctx, &auth_info_block.K, &auth_info_block.S);

    /* M1 = H(H(N) xor H(g), I, s, A, B, K) */
    /* S1 = H(N) */
    iWA_Crypto_Sha1HashBigNumbers(sha_ctx, S1, &auth_info_block.N, NULL);

    /* S2 = H(g) */
    iWA_Crypto_Sha1HashBigNumbers(sha_ctx, S2, &auth_info_block.g, NULL);

    /* S1 = S1 xor S2 */
    for(i = 0; i < S1->top; i++)   S1->d[i] ^= S2->d[i];

    /* M1 = H(S1, I, s, A, B, K) */
    iWA_Crypto_Sha1HashBigNumbers(sha_ctx, &auth_info_block.M1, S1, I, &auth_info_block.s, &auth_info_block.A, &auth_info_block.B, &auth_info_block.K, NULL);

    ret = 1;

#if 1    
    iWA_Log("username: %s", auth_info_block.username);
    iWA_Log("password: %s", auth_info_block.password);
    iWA_Log("I = H(username) : %s", BN_bn2hex(I));
    iWA_Log("p = H(username:password) : %s", BN_bn2hex(p));
    iWA_Log("g (received from server) : %s", BN_bn2hex(&auth_info_block.g));
    iWA_Log("N (received from server) : %s", BN_bn2hex(&auth_info_block.N));    
    iWA_Log("a = random 32 bytes : %s", BN_bn2hex(&auth_info_block.a));
    iWA_Log("A = g^a % N : %s", BN_bn2hex(&auth_info_block.A));
    iWA_Log("B (received from server) : %s", BN_bn2hex(&auth_info_block.B));
    iWA_Log("u = H(A, B) : %s", BN_bn2hex(u));
    iWA_Log("s (received from server) : %s", BN_bn2hex(&auth_info_block.s));
    iWA_Log("x = H(s, p) : %s", BN_bn2hex(x));
    iWA_Log("S = (B - k*(g^x%N)) ^ (a + u*x) % N : %s", BN_bn2hex(&auth_info_block.S));
    iWA_Log("K = H_interleave(S) : %s", BN_bn2hex(&auth_info_block.K));
    iWA_Log("M1 = H(H(N) xor H(g), I, s, A, B, K) : %s", BN_bn2hex(&auth_info_block.M1));
#endif

end:

    BN_free(I);
    BN_free(p);    
    BN_free(u);        
    BN_free(x);       
    BN_free(S1);     
    BN_free(S2);     
    BN_free(S3);     
    BN_CTX_free(bn_ctx);  
    iWA_Free((iWAuint8*)sha_ctx);
    
    return ret;
}

#if 0
iWAuint8* iWA_Auth_GetPacketBuf()
{
    return  auth_info_block.packet;
}
#endif

iWAuint32 iWA_Auth_GetClientBuild()
{
    return  auth_info_block.client_build;
}

iWAuint8* iWA_Auth_GetUsername()
{
    return  auth_info_block.username;
}

BIGNUM* iWA_Auth_GetK()
{
    return  &auth_info_block.K;
}





#if 1

void iWA_Auth_TestBn(void)
{
    BN_CTX *ctx;
    BIGNUM a1, a2, s;
    BIGNUM *g,*a,*N,*A;
    static iWAstruct_Auth_AuthInfoBlock info;


    iWA_Log("iWA_Auth_TestBn()");



#if 0
    /* test s = a1 + a2 */
    BN_init(&a1);
    BN_init(&a2);
    BN_init(&s);


    BN_bntest_rand(&a1,512,0,1);
    BN_bntest_rand(&a2,512,0,1);
    BN_add(&s,&a1,&a2);


#if 0
    iWA_Log("a1: %s", BN_bn2hex(&a1));
    iWA_Log("a2: %s", BN_bn2hex(&a2));    
    iWA_Log("s: %s", BN_bn2hex(&s));
#endif

    BN_free(&a1);
    BN_free(&a2);
    BN_free(&s);

#endif

#if 0

    /* test A = g^a % N */
    g=BN_new();
    a=BN_new();
    N=BN_new();
    A=BN_new();

    BN_hex2bn(&g, "7");
    BN_hex2bn(&a, "B4E8899F9A31CC8B000178D990F241E826EF4A441A9072E9EE178FE7F7C6F257");
    BN_hex2bn(&N, "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7");

    ctx = BN_CTX_new();
    BN_mod_exp(A, g, a, N, ctx);

#if 0
    iWA_Log("g: %s", BN_bn2hex(g));
    iWA_Log("a: %s", BN_bn2hex(a));    
    iWA_Log("N: %s", BN_bn2hex(N));
    iWA_Log("A: %s", BN_bn2hex(A));
#endif

    BN_free(g);
    BN_free(a);
    BN_free(N);
    BN_free(A);

    BN_CTX_free(ctx);    

#endif


#if 1

    iWA_Std_strcpy(info.username, "LOUHAO");
    iWA_Std_strcpy(info.password, "LOUHAO");   
    a = &info.g;
    BN_hex2bn(&a, "7");
    a = &info.N;
    BN_hex2bn(&a, "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7");
    a = &info.B;
    BN_hex2bn(&a, "252CA0AFDC7B727C185D1082DF41290418996C4AA1A088716EFEF7711028BDBA");
    a = &info.s;
    BN_hex2bn(&a, "98790A0C0151E9D7BD04C43BC8BDC0D4D70676129C0B565621EA407D10FFE7A5");
    
    iWA_Auth_CalculateClientSrpValue();
#endif

}

#endif




