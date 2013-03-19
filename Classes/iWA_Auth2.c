


#include "iWA.h"



typedef void (*iWApfunc_Auth_AuthMsgCb)(iWAuint32, iWAint32, void*);


#define iWAmacro_AUTH_INFO_USERNAME_MAXIUM             (32)
#define iWAmacro_AUTH_INFO_PASSWORD_MAXIUM            (32)

#define iWAmacro_AUTH_INFO_PACKET_MAXIUM                  (1024)
#define iWAmacro_AUTH_INFO_REALM_MAXIUM                   (5*10 + 1)



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
    iWAint8 bn_to_hex_buf[512];
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
static void handle_logon_server_packet(void);
static void handle_reg_server_packet(void);
static void handle_proof_server_packet(void);
static void handle_server_list_server_packet(void);
static iWAbool write_logon_client_packet(void);
static iWAbool write_reg_client_packet(void);
static iWAbool write_logreg_client_packet(iWAbool is_reg);
static iWAbool write_proof_client_packet(void);
static iWAbool write_server_list_client_packet(void);
static iWAint8* bn_to_hex(BIGNUM *bn);   /* BN_bn2hex NOT release memory, using this alternative */
static void calculate_password_hash(iWAint8 *username, iWAint8 *password, BIGNUM *hash);
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
        case iWAenum_AUTH_CMD_REG:
            handle_reg_server_packet();
            break;
        case iWAenum_AUTH_CMD_LOGON:
            handle_logon_server_packet();
            break;
            
        case iWAenum_AUTH_CMD_PROOF:
                /* send msg  iWAenum_AUTH_MSG_AUTH_OK */

                /* retrieve server list */     
            handle_proof_server_packet();
            break;
            
        case iWAenum_AUTH_CMD_SERVER_LIST:
            /* read list */
            handle_server_list_server_packet();

            /* close seesion */
            //iWA_World_InitSessionInfoBlock();

            /* send msg iWAenum_AUTH_MSG_AUTH_SERVER_LIST */

            break;       
            
            
            /* close seesion */

            /* send msg */
                    default:
            iWA_Log("server packet cmd: 0x%04x", cmd);

            
    }
}

static void print_auth_info_block(void)
{
    iWAuint16 i;
    iWAstruct_Auth_Server *svr;

    iWA_Log("print_auth_info_block()");

    iWA_Log("username : %s", auth_info_block.username);    
    iWA_Log("password : %s", auth_info_block.password);    

    iWA_Log("B : %s", bn_to_hex(&auth_info_block.B));
    iWA_Log("g : %s", bn_to_hex(&auth_info_block.g));
    iWA_Log("N : %s", bn_to_hex(&auth_info_block.N));    
    iWA_Log("s : %s", bn_to_hex(&auth_info_block.s));
    iWA_Log("M2 : %s", bn_to_hex(&auth_info_block.M2));    
    iWA_Log("a : %s", bn_to_hex(&auth_info_block.a));
    iWA_Log("A : %s", bn_to_hex(&auth_info_block.A));    
    iWA_Log("S : %s", bn_to_hex(&auth_info_block.S));
    iWA_Log("K : %s", bn_to_hex(&auth_info_block.K));
    iWA_Log("M1 : %s", bn_to_hex(&auth_info_block.M1)); 

    iWA_Log("server_num : %d", auth_info_block.server_num);

    for(i = 0; i < auth_info_block.server_num; i++)
    {
        svr = &auth_info_block.server[i];
        iWA_Log("[server %d] name:%s, address:%s, port:%d", i+1, svr->name, svr->address, svr->port);
    }
}


static void handle_reg_server_packet(void)
{
    IWAserverAuth__LogRegServer  *logreg;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint16 len;
    iWAuint32 result;
    iWA_Log("handle_reg_server_packet()");
    len = iWA_Net_ReadPacketUint16(p);
    logreg = i_waserver_auth__log_reg_server__unpack(NULL, len, p+4);
    result = (iWAuint32)logreg->result;   
    i_waserver_auth__log_reg_server__free_unpacked(logreg, NULL);
    disable_auth_seesion();
    iWA_Socket_DeinitSession();
    if(auth_info_block.func_reg_msg_cb != NULL) 
        ((iWApfunc_Auth_AuthMsgCb)auth_info_block.func_reg_msg_cb)(iWAenum_AUTH_CMD_REG, result, NULL);
}
static void handle_logon_server_packet(void)
{
    IWAserverAuth__LogRegServer  *logreg;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint16 len;
    iWAuint32 result;
    iWA_Log("handle_logon_server_packet()");
    len = iWA_Net_ReadPacketUint16(p);
    logreg = i_waserver_auth__log_reg_server__unpack(NULL, len, p+4);
    result = (iWAuint32)logreg->result;   
    if(logreg->result == I_WASERVER_AUTH__RESULT_CODE__SUCCESS)
    {
        if(logreg->has_b)   iWA_Net_ReadPacketBigNumber(logreg->b.data, logreg->b.len, &(auth_info_block.B)); 
        if(logreg->has_g)   iWA_Net_ReadPacketBigNumber(logreg->g.data, logreg->g.len, &(auth_info_block.g)); 
        if(logreg->has_n)   iWA_Net_ReadPacketBigNumber(logreg->n.data, logreg->n.len, &(auth_info_block.N)); 
        if(logreg->has_s)   iWA_Net_ReadPacketBigNumber(logreg->s.data, logreg->s.len, &(auth_info_block.s)); 
        calculate_client_SRP_value();
        write_proof_client_packet();
        send_auth_packet();
    }
    i_waserver_auth__log_reg_server__free_unpacked(logreg, NULL);
    if(auth_info_block.func_auth_msg_cb != NULL)    
        ((iWApfunc_Auth_AuthMsgCb)auth_info_block.func_auth_msg_cb)(iWAenum_AUTH_CMD_LOGON, result, NULL);         
}
static void handle_proof_server_packet(void)
{
    IWAserverAuth__ProofServer *proof;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint16 len;
    iWAuint32 result;
    iWA_Log("handle_proof_server_packet()");
    len = iWA_Net_ReadPacketUint16(p);
    proof = i_waserver_auth__proof_server__unpack(NULL, len, p+4);
    result = proof->result;
    i_waserver_auth__proof_server__free_unpacked(proof, NULL);
    if(result == I_WASERVER_AUTH__RESULT_CODE__SUCCESS)
    {
        if(auth_info_block.func_auth_msg_cb != NULL)    
            ((iWApfunc_Auth_AuthMsgCb)auth_info_block.func_auth_msg_cb)(iWAenum_AUTH_CMD_PROOF, result, NULL);
        write_server_list_client_packet();
        send_auth_packet();
    }
    else
    {
        disable_auth_seesion();
        iWA_Socket_DeinitSession();     
        if(auth_info_block.func_auth_msg_cb != NULL)    
            ((iWApfunc_Auth_AuthMsgCb)auth_info_block.func_auth_msg_cb)(iWAenum_AUTH_CMD_PROOF, result, NULL);
    }
}
static void handle_server_list_server_packet(void)
{
    IWAserverAuth__ServerListServer *list;
    IWAserverAuth__ServerListServer__Server *svr;
    IWAserverAuth__ServerListServer__Server__Character *chr;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint16 len;
    iWAuint16 i, j;
    iWAstruct_Auth_Server *server;
    iWAuint32 result;
    iWA_Log("handle_server_list_server_packet()");
    len = iWA_Net_ReadPacketUint16(p);
    list = i_waserver_auth__server_list_server__unpack(NULL, len, p+4);
    result = list->result;
    if(result == I_WASERVER_AUTH__RESULT_CODE__SUCCESS)
    {
        auth_info_block.server_num = (iWAuint16)((list->n_servers) < iWAmacro_AUTH_INFO_REALM_MAXIUM ? (list->n_servers) : (iWAmacro_AUTH_INFO_REALM_MAXIUM -1));
        for(i = 0; i < auth_info_block.server_num; i++)
        {
            svr = list->servers[i];
            server = &auth_info_block.server[i];
            iWA_Std_memset((void*)server, 0, sizeof(iWAstruct_Auth_Server));
            server->sid = svr->sid;
            server->region = svr->region;
            server->status = svr->status;
            iWA_Std_strcpy(server->name, svr->name);
            if(svr->hit != NULL)    iWA_Std_strcpy(server->hit, svr->hit);
            iWA_Std_strcpy(server->address, svr->address);
            server->port = svr->port;
            server->character_num = (svr->n_characters) < iWAmacro_WORLD_CHARACTER_NUM_MAXIUM ? (svr->n_characters) : (iWAmacro_WORLD_CHARACTER_NUM_MAXIUM - 1);
            for(j = 0; j < svr->n_characters; j++)
            {
                chr = svr->characters[j];
                server->character[j].cid = chr->cid;
                iWA_Std_strcpy(server->character[j].name, chr->name);
                server->character[j].grade = chr->grade;
                server->character[j].race = chr->race;
                server->character[j].nation = chr->nation;
            }
            server->character[j].cid = 0;
        }
        auth_info_block.server[i].sid = 0;  
    }
    else
    {
        auth_info_block.server_num = 0;
        auth_info_block.server[0].sid = 0;  
    }
    i_waserver_auth__server_list_server__free_unpacked(list, NULL);
    disable_auth_seesion();
    iWA_Socket_DeinitSession();
    if(auth_info_block.func_auth_msg_cb != NULL)    
        ((iWApfunc_Auth_AuthMsgCb)auth_info_block.func_auth_msg_cb)(iWAenum_AUTH_CMD_SERVER_LIST, result, (void*)&auth_info_block.server[0]);
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
    BIGNUM H;

    iWA_Log("write_logreg_client_packet(%d)", is_reg);

    i_waserver_auth__log_reg_client__init(&logreg);

#if   _iWA_CLIENT_
    logreg.gamename = "iWA";
#else
    logreg.gamename = "iWA1";
#endif
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


    if(is_reg)
    {
        BN_init(&H);    
        calculate_password_hash(auth_info_block.username, auth_info_block.password, &H);
        logreg.password_hash = bn_to_hex(&H);
    }
    auth_info_block.packet_len = i_waserver_auth__log_reg_client__pack(&logreg, p+4);
    iWA_Net_WritePacketUint16(p, auth_info_block.packet_len);
    iWA_Net_WritePacketUint16(p+2, is_reg ? iWAenum_AUTH_CMD_REG : iWAenum_AUTH_CMD_LOGON);
    auth_info_block.packet_len += 4;

    return 1;
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

    






static iWAbool write_server_list_client_packet(void) 
{
    IWAserverAuth__ServerListClient list;
    iWAuint8 *p = auth_info_block.packet;
    iWAuint32 result;
    
    iWA_Log("write_server_list_client_packet()");

    i_waserver_auth__server_list_client__init(&list);

    list.reserved = 0;

    auth_info_block.packet_len = i_waserver_auth__server_list_client__pack(&list, p+4);
    iWA_Net_WritePacketUint16(p, auth_info_block.packet_len);
    iWA_Net_WritePacketUint16(p+2, iWAenum_AUTH_CMD_SERVER_LIST);
    auth_info_block.packet_len += 4;
    
    return 1;
}






        
        




static iWAint8* bn_to_hex(BIGNUM *bn)   /* BN_bn2hex NOT release memory, using this alternative */
{



    iWAint32 i,j,v,z=0;
    iWAint8 *p;
    static const iWAint8 hex[]="0123456789ABCDEF";
    iWAint32 len;
    p = auth_info_block.bn_to_hex_buf;
    if (bn->neg)    *(p++) = '-';
    if (BN_is_zero(bn))     *(p++) = '0';
    for (i = bn->top - 1; i >= 0; i--)
    {
        for (j = BN_BITS2 - 8; j >= 0; j -= 8)
        {
            /* strip leading zeros */
            v = ((iWAint32)(bn->d[i] >> j)) & 0xff;
            if (z || (v != 0))
            {
                *(p++) = hex[v >> 4];
                *(p++) = hex[v & 0x0f];
                z = 1;
            }
        }
    }
    *p = 0x00;
    return auth_info_block.bn_to_hex_buf;
}
static void calculate_password_hash(iWAint8 *username, iWAint8 *password, BIGNUM *hash)
{
    SHA1Context sha_ctx;    
    /* calculate H(username:password) */
    SHA1Reset(&sha_ctx);
    SHA1Input(&sha_ctx, username, iWA_Std_strlen(username));
    SHA1Input(&sha_ctx, ":", 1);
    SHA1Input(&sha_ctx, password, iWA_Std_strlen(password));    
    iWA_Crypto_Sha1ResultBigNumber(&sha_ctx, hash);
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
    calculate_password_hash(auth_info_block.username, auth_info_block.password, p);
#if 0
    SHA1Reset(sha_ctx);
    SHA1Input(sha_ctx, auth_info_block.username, iWA_Std_strlen(auth_info_block.username));
    SHA1Input(sha_ctx, ":", 1);
    SHA1Input(sha_ctx, auth_info_block.password, iWA_Std_strlen(auth_info_block.password));    
    iWA_Crypto_Sha1ResultBigNumber(sha_ctx, p);
#endif

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
    iWA_Log("I = H(username) : %s", bn_to_hex(I));
    iWA_Log("p = H(username:password) : %s", bn_to_hex(p));
    iWA_Log("g (received from server) : %s", bn_to_hex(&auth_info_block.g));
    iWA_Log("N (received from server) : %s", bn_to_hex(&auth_info_block.N));    
    iWA_Log("a = random 32 bytes : %s", bn_to_hex(&auth_info_block.a));
    iWA_Log("A = g^a % N : %s", bn_to_hex(&auth_info_block.A));
    iWA_Log("B (received from server) : %s", bn_to_hex(&auth_info_block.B));
    iWA_Log("u = H(A, B) : %s", bn_to_hex(u));
    iWA_Log("s (received from server) : %s", bn_to_hex(&auth_info_block.s));
    iWA_Log("x = H(s, p) : %s", bn_to_hex(x));
    iWA_Log("S = (B - k*(g^x%N)) ^ (a + u*x) % N : %s", bn_to_hex(&auth_info_block.S));
    iWA_Log("K = H_interleave(S) : %s", bn_to_hex(&auth_info_block.K));
    iWA_Log("M1 = H(H(N) xor H(g), I, s, A, B, K) : %s", bn_to_hex(&auth_info_block.M1));
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


static void auth_msg_callback(iWAuint32 cmd, iWAint32 para1, void *para2)
{

    iWAstruct_Auth_Server *server;
    iWAstruct_Character  *character;
    iWAint32 i;

    iWA_Log("auth_msg_callback cmd:%d para1:%d", cmd, para1);
    
    switch(cmd)
    {
        case iWAenum_AUTH_CMD_REG:
            if(para1 == I_WASERVER_AUTH__RESULT_CODE__SUCCESS)
            {
                iWA_Log("Register user success");
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__UNPACK_MESSAGE_ERROR)
            {
                iWA_Log("Register user fail, unpack message error");
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__REG_USERNAME_EMPTY)
            {
                iWA_Log("Register user fail, username is empty");            
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__REG_PASSWORD_EMPTY)
            {
                iWA_Log("Register user fail, password is empty");            
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__REG_DB_QUERY_ERROR)
            {
                iWA_Log("Register user fail, query db error");            
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__REG_USERNAME_ALREADY_EXISTS)
            {
                iWA_Log("Register user fail, username already exists");            
            }            
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__REG_DB_INSERT_ERROR)
            {
                iWA_Log("Register user fail, insert db error");                 
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR)
            {
                iWA_Log("Register user fail, unknown error");
            }
#if 1
                iWA_Auth_DoAuthSample();
#endif
            break;
        case iWAenum_AUTH_CMD_LOGON:
            if(para1 == I_WASERVER_AUTH__RESULT_CODE__SUCCESS)
            {
                iWA_Log("Logon user in proofing");
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__UNPACK_MESSAGE_ERROR)
            {
                iWA_Log("Logon user fail, unpack message error");
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__LOGON_USERNAME_EMPTY)
            {
                iWA_Log("Logon user fail, username is empty");            
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__LOGON_DB_QUERY_ERROR)
            {
                iWA_Log("Logon user fail, query db error");            
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__LOGON_ACCOUNT_NOEXIST)
            {
                iWA_Log("Logon user fail, account not exist");                 
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR)
            {
                iWA_Log("Logon user fail, unknown error");
            }
            break;
        case iWAenum_AUTH_CMD_PROOF:
            if(para1 == I_WASERVER_AUTH__RESULT_CODE__SUCCESS)
            {
                iWA_Log("Logon user pass, getting server list");
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__UNPACK_MESSAGE_ERROR)
            {
                iWA_Log("Logon user fail, unpack message error");
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__PROOF_AVALUE_INCORRECT)
            {
                iWA_Log("Logon user fail, A value incorrect");            
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__PROOF_M1VALUE_INCORRECT)
            {
                iWA_Log("Logon user fail, M1 value incorrect");            
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__PROOF_MVALUE_UNMATCH)
            {
                iWA_Log("Logon user fail, M value unmatch");                 
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__PROOF_DB_UPDATE_ERROR)
            {
                iWA_Log("Logon user fail, db update error");                 
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR)
            {
                iWA_Log("Logon user fail, unknown error");
            }
            break;
        case iWAenum_AUTH_CMD_SERVER_LIST:
            if(para1 == I_WASERVER_AUTH__RESULT_CODE__SUCCESS)
            {
            iWA_Log("Game Server List:");

            /* read server list */
                server = (iWAstruct_Auth_Server*)para2;
                while(server->sid > 0)
            {
                    iWA_Log("[Server%d %s]  %s:%d", server->sid, server->name, server->address, server->port);
                    for(i = 0; i < server->character_num; i++)
                    {
                        character = &server->character[i];
                        iWA_Log("    character<%d> name:%s, grade:%d, race:%d, nation:%d", character->cid, character->name, character->grade, character->race, character->nation);
                    }
                ++server;
            }

#if 1
            /* connect first game server */
                server = (iWAstruct_Auth_Server*)para2;
                if(server->sid > 0)
            {
                iWA_World_Init();
                iWA_World_StartSample(server->address, server->port);
            }
#endif
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__UNPACK_MESSAGE_ERROR)
            {
                iWA_Log("Get server list fail, unpack message error");
            }
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__SERVER_LIST_DB_QUERY_ERROR)
            {
                iWA_Log("Get server list fail, db query error");                 
            }            
            else if(para1 == I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR)
            {
                iWA_Log("Get server list fail, unknown error");
            }
            break;        
    }

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


