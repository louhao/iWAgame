


#include "iWA.h"



typedef void (*iWApfunc_Auth_AuthMsgCb)(iWAuint32, void*);


#define iWAmacro_AUTH_INFO_USERNAME_MAXIUM             (32)
#define iWAmacro_AUTH_INFO_PASSWORD_MAXIUM            (32)

#define iWAmacro_AUTH_INFO_PACKET_MAXIUM                  (1024)
#define iWAmacro_AUTH_INFO_REALM_MAXIUM                   (5*10)



typedef struct
{
    void* func_reg_msg_cb;
    void* func_auth_msg_cb;
    iWAuint16 session_valid;      
    iWAuint16 client_build;
    iWAuint8 username[iWAmacro_AUTH_INFO_USERNAME_MAXIUM];
    iWAuint8 password[iWAmacro_AUTH_INFO_PASSWORD_MAXIUM];
    iWAuint8 packet[iWAmacro_AUTH_INFO_PACKET_MAXIUM];    
    iWAuint32 packet_len;
    BIGNUM B, g, N, s, M2;  /* received from server */
    BIGNUM a, A, S, K, M1;  /* generate at client */
    iWAuint16 server_num;   
    iWAstruct_Auth_Server  server[iWAmacro_AUTH_INFO_REALM_MAXIUM];
}iWAstruct_Auth_AuthInfoBlock;


static iWAstruct_Auth_AuthInfoBlock auth_info_block = {0};

static void print_auth_info_block(void);

static void enable_auth_seesion(void);
static void disable_auth_seesion(void);
static iWAbool check_auth_session(void);

static iWAuint32 split_auth_packet(iWAuint8 *pkt, iWAuint32 len);
static iWAbool send_auth_packet(void);
static iWAbool receive_auth_packet(void);
static void handle_auth_packet(void);

static iWAbool write_logon_client_packet(void);
static iWAbool write_reg_client_packet(void);
static iWAbool write_logreg_client_packet(iWAbool is_reg);
static iWAuint32 read_logon_server_packet(void);
static iWAuint32 read_reg_server_packet(void);
static iWAbool write_proof_client_packet(void);
static iWAbool read_proof_server_packet(void);
static iWAbool write_server_list_client_packet(void);
static iWAbool read_server_list_server_packet(void);

static iWAbool calculate_client_SRP_value(void);


static void enable_auth_seesion(void)
{
    auth_info_block.session_valid = 1;
}

static void disable_auth_seesion(void)
{
    auth_info_block.session_valid = 0;
}

static iWAbool check_auth_session(void)
{
    return !!auth_info_block.session_valid;
}


static iWAuint32 split_auth_packet(iWAuint8 *pkt, iWAuint32 len)
{
    iWAuint16 size;

    size = iWA_Net_ReadPacketUint16(pkt);

    return size+4;
}


static iWAbool send_auth_packet(void)
{
    iWA_Log("send_auth_packet()");

    if(!check_auth_session())     return 0;

    return iWA_Socket_SendPacket(auth_info_block.packet, auth_info_block.packet_len);    
}

static iWAbool receive_auth_packet(void)
{
    if(!check_auth_session())     return 0;

    return iWA_Socket_ReceivePacket(auth_info_block.packet, &auth_info_block.packet_len);
}

static void handle_auth_packet(void)
{
    iWAuint32 ret, msg;
    iWAuint16 cmd;
    
    iWA_Log("handle_auth_packet()");

    cmd = iWA_Net_ReadPacketUint16(auth_info_block.packet+2);
    
    switch(cmd)
    {
        case iWAenum_AUTH_CMD_LOGON:
            if(read_logon_server_packet() == I_WASERVER_AUTH__LOG_REG_SERVER__RESULT_CODE__OK)
            {
                calculate_client_SRP_value();
                write_proof_client_packet();
                send_auth_packet();
            }    
            break;
            
        case iWAenum_AUTH_CMD_PROOF:
            if(read_proof_server_packet() == I_WASERVER_AUTH__PROOF_SERVER__RESULT_CODE__OK)
            {
                /* send msg  iWAenum_AUTH_MSG_AUTH_OK */
                if(auth_info_block.func_auth_msg_cb != NULL)    
                    ((iWApfunc_Auth_AuthMsgCb)auth_info_block.func_auth_msg_cb)(iWAenum_AUTH_MSG_AUTH_OK, NULL);

                /* retrieve server list */     
                write_server_list_client_packet();
                send_auth_packet();
            }
            break;
            
        case iWAenum_AUTH_CMD_SERVER_LIST:
            /* read list */
            read_server_list_server_packet();
            print_auth_info_block();

            /* close seesion */
            disable_auth_seesion();
            iWA_Socket_DeinitSession();
            //iWA_World_InitSessionInfoBlock();

            /* send msg iWAenum_AUTH_MSG_AUTH_SERVER_LIST */
            if(auth_info_block.func_auth_msg_cb != NULL)    
                ((iWApfunc_Auth_AuthMsgCb)auth_info_block.func_auth_msg_cb)(iWAenum_AUTH_MSG_AUTH_SERVER_LIST, (void*)&auth_info_block.server[0]);

            break;       
            
        case iWAenum_AUTH_CMD_REG:
            ret = read_reg_server_packet();
            
            /* close seesion */
            disable_auth_seesion();
            iWA_Socket_DeinitSession();

            /* send msg */
            if(auth_info_block.func_reg_msg_cb != NULL) 
            {
                switch(ret)
                {
                    case I_WASERVER_AUTH__LOG_REG_SERVER__RESULT_CODE__OK:
                        msg = iWAenum_AUTH_MSG_REG_OK;
                        break;
                    default:
                        msg = iWAenum_AUTH_MSG_REG_CREATE_FAIL;
                        break;
                }

                ((iWApfunc_Auth_AuthMsgCb)auth_info_block.func_reg_msg_cb)(msg, NULL);
            }
            
            break;
    }
}

static void print_auth_info_block(void)
{
    iWAuint16 i;
    iWAstruct_Auth_Server *svr;

    iWA_Log("print_auth_info_block()");

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

    iWA_Log("server_num : %d", auth_info_block.server_num);

    for(i = 0; i < auth_info_block.server_num; i++)
    {
        svr = &auth_info_block.server[i];
        iWA_Log("[server %d] name:%s, address:%s, port:%d", i+1, svr->name, svr->address, svr->port);
    }
}


static iWAbool write_logon_client_packet(void)
{
    iWA_Log("write_logon_client_packet()");

    return write_logreg_client_packet(0);
}

static iWAbool write_reg_client_packet(void)
{
    iWA_Log("write_reg_client_packet()");

    return write_logreg_client_packet(1);
}


static iWAbool write_logreg_client_packet(iWAbool is_reg)
{
    IWAserverAuth__LogRegClient logreg;
    iWAuint8 *p = auth_info_block.packet;

    iWA_Log("write_logreg_client_packet(%d)", is_reg);

    i_waserver_auth__log_reg_client__init(&logreg);

    logreg.gamename = "iWA1";
    logreg.version1 = 0;
    logreg.version2 = 0;
    logreg.version3 = 1;

    auth_info_block.client_build = 1;
    logreg.build =  auth_info_block.client_build;

#if defined(TARGET_OS_IPHONE) || defined(TARGET_IPHONE_SIMULATOR)
    logreg.platform = "iOS";
#elif defined(ANDROID)
    logreg.platform = 'Android";
#elif defined(WIN32)
    logreg.platform = 'WIN32";
#else
    logreg.platform = 'Unknown";
#endif

    logreg.os = logreg.platform;
    logreg.country = "enUS";
    logreg.timezone_bias = 0; 
    logreg.username = auth_info_block.username;
    logreg.password = is_reg ? auth_info_block.password : NULL;

    auth_info_block.packet_len = i_waserver_auth__log_reg_client__pack(&logreg, p+4);
    iWA_Net_WritePacketUint16(p, auth_info_block.packet_len);
    iWA_Net_WritePacketUint16(p+2, is_reg ? iWAenum_AUTH_CMD_REG : iWAenum_AUTH_CMD_LOGON);
    auth_info_block.packet_len += 4;

    return 1;
}

static iWAuint32 read_logon_server_packet(void)
{
    IWAserverAuth__LogRegServer  *logreg;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint16 len;
    iWAuint32 result;
    
    iWA_Log("read_logon_server_packet()");

    len = iWA_Net_ReadPacketUint16(p);
    logreg = i_waserver_auth__log_reg_server__unpack(NULL, len, p+4);
    result = (iWAuint32)logreg->result;   

    if(logreg->result == I_WASERVER_AUTH__LOG_REG_SERVER__RESULT_CODE__OK)
    {
        iWA_Net_ReadPacketBigNumber(logreg->b.data, logreg->b.len, &(auth_info_block.B)); 
        iWA_Net_ReadPacketBigNumber(logreg->g.data, logreg->g.len, &(auth_info_block.g)); 
        iWA_Net_ReadPacketBigNumber(logreg->n.data, logreg->n.len, &(auth_info_block.N)); 
        iWA_Net_ReadPacketBigNumber(logreg->s.data, logreg->s.len, &(auth_info_block.s)); 
    }
    
    i_waserver_auth__log_reg_server__free_unpacked(logreg, NULL);
    
    return result;
}

static iWAuint32 read_reg_server_packet(void)
{
    IWAserverAuth__LogRegServer  *logreg;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint16 len;
    iWAuint32 result;

    iWA_Log("read_reg_server_packet()");

    len = iWA_Net_ReadPacketUint16(p);
    logreg = i_waserver_auth__log_reg_server__unpack(NULL, len, p+4);
    result = (iWAuint32)logreg->result;   

    i_waserver_auth__log_reg_server__free_unpacked(logreg, NULL);

    return result;
}




static iWAbool write_proof_client_packet(void)
{
    IWAserverAuth__ProofClient proof;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint8   A[32];              
    iWAuint8   M1[20];   
    
    iWA_Log("write_proof_client_packet()");

    i_waserver_auth__proof_client__init(&proof);

    iWA_Net_WritePacketBigNumber(A, &(auth_info_block.A));
    proof.a.data = A;
    proof.a.len = 32;

    iWA_Net_WritePacketBigNumber(M1, &(auth_info_block.M1));   
    proof.m1.data = M1;
    proof.m1.len = 20;

    auth_info_block.packet_len = i_waserver_auth__proof_client__pack(&proof, p+4);
    iWA_Net_WritePacketUint16(p, auth_info_block.packet_len);
    iWA_Net_WritePacketUint16(p+2, iWAenum_AUTH_CMD_PROOF);
    auth_info_block.packet_len += 4;

    return 1;
}

static iWAbool read_proof_server_packet(void)
{
    IWAserverAuth__ProofServer *proof;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint16 len;
    iWAuint32 result;
    
    iWA_Log("read_proof_server_packet()");

    len = iWA_Net_ReadPacketUint16(p);

    proof = i_waserver_auth__proof_server__unpack(NULL, len, p+4);
    result = proof->result;

    iWA_Net_ReadPacketBigNumber(proof->m2.data, proof->m2.len, &(auth_info_block.M2)); 

    i_waserver_auth__proof_server__free_unpacked(proof, NULL);

    return result;
}

static iWAbool write_server_list_client_packet(void) 
{
    IWAserverAuth__ServerListClient list;
    iWAuint8 *p = auth_info_block.packet;
    
    iWA_Log("write_server_list_client_packet()");

    i_waserver_auth__server_list_client__init(&list);

    list.reserved = 0;

    auth_info_block.packet_len = i_waserver_auth__server_list_client__pack(&list, p+4);
    iWA_Net_WritePacketUint16(p, auth_info_block.packet_len);
    iWA_Net_WritePacketUint16(p+2, iWAenum_AUTH_CMD_SERVER_LIST);
    auth_info_block.packet_len += 4;
    
    return 1;
}

static iWAbool read_server_list_server_packet(void)
{
    IWAserverAuth__ServerListServer *list;
    IWAserverAuth__ServerListServer__Server *svr;
    IWAserverAuth__ServerListServer__Server__Character *chr;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint16 len;
    iWAuint16 i;
    iWAstruct_Auth_Server *server;

    iWA_Log("read_server_list_server_packet()");

    len = iWA_Net_ReadPacketUint16(p);

    list = i_waserver_auth__server_list_server__unpack(NULL, len, p+4);

    /* fill iWAstruct_Auth_Server */
    auth_info_block.server_num = (iWAuint16)list->num;
    for(i = 0; i < auth_info_block.server_num; i++)
    {
        svr = list->servers[i];
        server = &auth_info_block.server[i];
        iWA_Std_memset((void*)server, 0, sizeof(iWAstruct_Auth_Server));
        server->region = svr->region;
        server->status = svr->status;
        iWA_Std_strcpy(server->name, svr->name);
        iWA_Std_strcpy(server->address, svr->address);
        server->port = svr->port;

        server->character_num = svr->n_characters;
        
        if(server->character_num > 0)
        {
            chr = svr->characters[0];
        
            server->character_grade = chr->grade;
            iWA_Std_strcpy(server->character_name, chr->name);
            server->character_race = chr->race;
            server->character_nation = chr->nation;
        }
    }

    auth_info_block.server[i].region = 0;   /* set server list END flag */

    i_waserver_auth__server_list_server__free_unpacked(list, NULL);

    return 1;
}





static iWAbool calculate_client_SRP_value(void)
{
#if   _iWA_CLIENT_
    BIGNUM *I;

    I = &auth_info_block.A;
    BN_hex2bn(&I, "46301CBF4BAB8CB63FA7635B4ED811924539FB3A8473DFA46AA61D6DC868CF67");
    I = &auth_info_block.M1;
    BN_hex2bn(&I, "7497BCA19AFC28F2777764FB33A1034BA80E63FC");
    I = &auth_info_block.K;
    BN_hex2bn(&I, "D10FDB0FB4FDC4893290764BEDE4500631EB2E3FCCBDE656A710E8A6FA6736933E9C63562D895729");    
    return 1;

#else

    iWAbool ret = 0;
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *I = BN_new(), *p = BN_new(), *u = BN_new(), *x = BN_new();
    BIGNUM *S1 = BN_new(), *S2 = BN_new(), *S3 = BN_new(), *k =  BN_new();
    SHA1Context *sha_ctx = (SHA1Context*)iWA_Malloc(sizeof(SHA1Context));
    iWAuint32 i;

    iWA_Log("calculate_client_SRP_value()");



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

#endif
}


void iWA_Auth_Init(void)
{
    iWA_Log("iWA_Auth_Init()");

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
}

void iWA_Auth_Deinit()
{
    iWA_Log("iWA_Auth_Deinit()");

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

    iWA_Std_memset((void*)&auth_info_block, 0, sizeof(iWAstruct_Auth_AuthInfoBlock));
}

iWAuint32 iWA_Auth_GetClientBuild(void)
{
    return  auth_info_block.client_build;
}

iWAuint8* iWA_Auth_GetUsername(void)
{
    return  auth_info_block.username;
}

BIGNUM* iWA_Auth_GetK(void)
{
    return  &auth_info_block.K;
}

iWAbool iWA_Auth_DoAuth(iWAuint8 *server, iWAuint16 port, iWAuint8 *username, iWAuint8 *password, void *msg_cb)
{
    iWA_Log("iWA_Auth_DoAuth()");

    if(server == NULL || username == NULL || password == NULL)  return 0;

    iWA_Std_strcpy(auth_info_block.username, username);
    iWA_Std_strcpy(auth_info_block.password, password);    
    auth_info_block.func_auth_msg_cb = msg_cb;

    if(!iWA_Socket_InitSession(server, port, 1024, 1024, (void*)split_auth_packet, 2, NULL))    return 0;
    
    enable_auth_seesion();
    write_logon_client_packet();
    send_auth_packet();

    return 1;
}

iWAbool iWA_Auth_DoReg(iWAuint8 *server, iWAuint16 port, iWAuint8 *username, iWAuint8 *password, void *msg_cb)
{
    iWA_Log("iWA_Auth_DoAuth()");

    if(server == NULL || username == NULL || password == NULL)  return 0;

    iWA_Std_strcpy(auth_info_block.username, username);
    iWA_Std_strcpy(auth_info_block.password, password);    
    auth_info_block.func_reg_msg_cb = msg_cb;

    if(!iWA_Socket_InitSession(server, port, 1024, 1024, (void*)split_auth_packet, 2, NULL))    return 0;
    
    enable_auth_seesion();
    write_reg_client_packet();
    send_auth_packet();

    return 1;    
}

void iWA_Auth_DoReceive(void)
{
    if(receive_auth_packet())   handle_auth_packet();
}


/****************************  iWA_Auth_DoAuth()  usage sample ***********************************/


static void auth_msg_callback(iWAuint32 msg, void *data)
{

    iWAstruct_Auth_Server *server;

    iWA_Log("auth_msg_callback msg: 0x%02x", msg);
    
    switch(msg)
    {
        case iWAenum_AUTH_MSG_AUTH_OK:
            iWA_Log("Pass Auth, Start Getting Server List");
            break;
        case iWAenum_AUTH_MSG_AUTH_CONNECT_ERROR:
            iWA_Log("Connect Server Error");
            break;
         case iWAenum_AUTH_MSG_AUTH_INVALID_USERNAME:
            iWA_Log("Username Invalid");
            break;
        case iWAenum_AUTH_MSG_AUTH_INVALID_PASSWORD:
            iWA_Log("Password Incorrect");
            break;
        case iWAenum_AUTH_MSG_AUTH_SERVER_LIST:
            iWA_Log("Game Server List:");

            /* read server list */
            server = (iWAstruct_Auth_Server*)data;
            while(server->region > 0)
            {
                iWA_Log("[Server %s]  %s:%d", server->name, server->address, server->port);
                ++server;
            }

#if 0
            /* connect first game server */
            server = (iWAstruct_Auth_Server*)data;
            if(server->region > 0)
            {
                iWA_World_Init();
                iWA_World_StartSample(server->address, server->port);
            }
#endif

            break;
        case iWAenum_AUTH_MSG_REG_OK:
            iWA_Log("Create Account OK");
            break;
        case iWAenum_AUTH_MSG_REG_CONNECT_ERROR:
            iWA_Log("Connect Server Error");
            break;
        case iWAenum_AUTH_MSG_REG_USERNAME_EXIST:
            iWA_Log("Username already exists");
            break;
        case iWAenum_AUTH_MSG_REG_CREATE_FAIL:
            iWA_Log("Create Account Fail");
            break;        
    }

#if 0
    if(msg >= iWAenum_AUTH_MSG_REG_OK)
        iWA_Auth_DoAuthSample();
#endif
}

#define _AUTH_USERNAME_        "LOUHAO3"
#define _AUTH_PASSWORD_        "LOUHAO3"

iWAbool iWA_Auth_DoAuthSample(void)
{
    return iWA_Auth_DoAuth(_SERVER_IP_, 3724, _AUTH_USERNAME_, _AUTH_PASSWORD_, (void*)auth_msg_callback);
}

iWAbool iWA_Auth_DoRegSample(void)
{
    return iWA_Auth_DoReg(_SERVER_IP_, 3724, _AUTH_USERNAME_, _AUTH_PASSWORD_, (void*)auth_msg_callback);
}


