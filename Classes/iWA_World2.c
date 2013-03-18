

#include "iWA.h"


typedef void (*iWApfunc_World_WorldMsgCb)(iWAuint32 msg, iWAint32 para1, void* para2);

#define iWAmacro_WORLD_SEESION_INFO_USERNAME_MAXIUM             (64)
#define iWAmacro_WORLD_SEESION_INFO_PACKET_MAXIUM                  (1024)
#define iWAmacro_WORLD_SEESION_INFO_KEY_SIZE             (40)

#define iWAmacro_WORLD_CHARACTER_NAME_MAXIUM          (32)
#define iWAmacro_WORLD_CHARACTER_NUM_MAXIUM          (10)

typedef struct
{
    void *func_msg_cb;
    iWAuint8 username[iWAmacro_WORLD_SEESION_INFO_USERNAME_MAXIUM];
    iWAuint8 packet[iWAmacro_WORLD_SEESION_INFO_PACKET_MAXIUM];    
    iWAuint32 packet_len;
    iWAuint8 key[iWAmacro_WORLD_SEESION_INFO_KEY_SIZE];
    iWAuint16 key_size;
    iWAuint8 send_i, send_j, recv_i, recv_j;
    iWAuint32 client_seed;
    iWAbool do_crypto;
    BIGNUM K, D;
    iWAstruct_Character  character[iWAmacro_WORLD_CHARACTER_NUM_MAXIUM];
    iWAuint8 character_num;
    iWAuint8 session_valid;
}iWAstruct_World_SessionInfoBlock;

static iWAstruct_World_SessionInfoBlock world_session_info_block = {0};


#define iWAmacro_WORLD_PACKET_HEADER_SIZE    (4)
#define iWAmacro_WORLD_PACKET_HEADER_SIZE    (4)

static void enable_world_seesion(void);
static void disable_world_seesion(void);
static iWAbool check_world_session(void);
static void print_world_session_info_block(void);

static iWAbool send_world_packet(void);
static iWAbool receive_world_packet(void);
static void handle_world_packet(void);

static iWAbool read_server_packet_header(iWAuint8* packet, iWAuint16 *size, iWAuint16 *cmd);
static void write_client_packet_header(iWAuint8* packet, iWAuint16 size, iWAuint16 cmd);
static iWAuint32 split_world_packet(iWAuint8 *pkt, iWAuint32 len);
static void decrypt_world_packet(iWAuint8 *pkt, iWAuint32 len);

static void handle_auth_challenge_server_packet(void);
static void handle_auth_response_server_packet(void);
static void handle_char_enum_server_packet(void);
static void handle_char_create_server_packet(void);
static void handle_char_delete_server_packet(void);

static iWAbool write_auth_session_client_packet(void);
static iWAbool write_char_enum_client_packet(void);
static iWAbool write_player_login_client_packet(void);
static iWAbool write_char_create_client_packet(void);
static iWAbool write_char_delete_client_packet(void);


static void enable_world_seesion(void)
{
    world_session_info_block.session_valid = 1;
}

static void disable_world_seesion(void)
{
    world_session_info_block.session_valid = 0;
}

static iWAbool check_world_session(void)
{
    return !!world_session_info_block.session_valid;
}

static void print_world_session_info_block(void)
{
    iWA_Log("print_world_session_info_block()");

    iWA_Dump(world_session_info_block.key, world_session_info_block.key_size);
}


static iWAbool send_world_packet(void)
{
    iWA_Log("send_world_packet()");

    if(!check_world_session())     return 0;

    return iWA_Socket_SendPacket(world_session_info_block.packet, world_session_info_block.packet_len);    
}

static iWAbool receive_world_packet(void)
{
    if(!check_world_session())     return 0;

    return iWA_Socket_ReceivePacket(world_session_info_block.packet, &world_session_info_block.packet_len);
}


static void handle_world_packet(void)
{
    iWAuint16 size, cmd;

    iWA_Log("handle_world_packet()");
    
    if(!read_server_packet_header(world_session_info_block.packet, &size, &cmd))  return;

    switch(cmd)
    {
        case iWAenum_GAME_CMD_AUTH_CHANLLEGE:
            handle_auth_challenge_server_packet();
            write_auth_session_client_packet();
            send_world_packet();
            break;
            
        case iWAenum_GAME_CMD_AUTH_RESPONSE:
            handle_auth_response_server_packet();
            break;

        case iWAenum_GAME_CMD_CHAR_ENUM:
            handle_char_enum_server_packet();
            break;

        case iWAenum_GAME_CMD_CHAR_DELETE:
            handle_char_delete_server_packet();
            break;
            
        case iWAenum_GAME_CMD_CHAR_CREATE:
            handle_char_create_server_packet();
            break;  
        

        default:
            iWA_Log("server packet cmd: 0x%04x", cmd);
    }    
}



static iWAbool read_server_packet_header(iWAuint8* packet, iWAuint16 *size, iWAuint16 *cmd)
{
    iWAuint32 t;
    iWAuint8 x;

    //iWA_Log("read_server_packet_header()");

    if(packet == NULL || size == NULL || cmd == NULL)     return 0;

    //iWA_Dump(packet, iWAmacro_WORLD_PACKET_HEADER_SIZE);

    *size = iWA_Net_ReadPacketUint16(packet);
    *cmd = iWA_Net_ReadPacketUint16(packet+2);
    
    return 1;
}

static void write_client_packet_header(iWAuint8* packet, iWAuint16 size, iWAuint16 cmd)
{
    iWAuint32 t;
    iWAuint8 x;

    iWA_Log("write_client_packet_header()");

    if(packet == NULL)     return;
  
    iWA_Net_WritePacketUint16(packet, size);
    iWA_Net_WritePacketUint16(packet+2, cmd);

    iWA_Dump(packet, iWAmacro_WORLD_PACKET_HEADER_SIZE);

    if(world_session_info_block.do_crypto)
    {

        for(t = 0; t < iWAmacro_WORLD_PACKET_HEADER_SIZE; t++)
        {
            world_session_info_block.send_i %= world_session_info_block.key_size;
            x = (packet[t] ^ world_session_info_block.key[world_session_info_block.send_i]) + world_session_info_block.send_j;
            ++world_session_info_block.send_i;
            packet[t] = world_session_info_block.send_j = x;
        
        }
    }

    iWA_Dump(packet, iWAmacro_WORLD_PACKET_HEADER_SIZE);
}


static iWAuint32 split_world_packet(iWAuint8 *pkt, iWAuint32 len)
{
    iWAuint32 t;
    iWAuint8 x;
    iWAuint16 size, cmd;
    iWAuint8 recv_i, recv_j;

    iWA_Log("split_world_packet()");

    if(pkt == NULL || len < iWAmacro_WORLD_PACKET_HEADER_SIZE)   return 0;

    iWA_Dump(pkt, iWAmacro_WORLD_PACKET_HEADER_SIZE);

    if(!world_session_info_block.do_crypto)
    {
        size = iWA_Net_ReadPacketUint16(pkt);
        //cmd = iWA_Net_ReadPacketUint16(pkt+2);

        return size+4;

        //if(cmd == iWAenum_GAME_CMD_AUTH_CHANLLEGE || cmd == iWAenum_GAME_CMD_AUTH_RESPONSE)   return size+4;

        /* this packet already been encrypted, change state */
        //world_session_info_block.do_crypto = 1;
    }

    recv_i = world_session_info_block.recv_i;
    recv_j = world_session_info_block.recv_j;
    for(t = 0; t < iWAmacro_WORLD_PACKET_HEADER_SIZE; t++)
    {
        recv_i %= world_session_info_block.key_size;
        x = (pkt[t] - recv_j) ^ world_session_info_block.key[recv_i];
        ++recv_i;
        recv_j = pkt[t];
        pkt[t] = x;
    
    }
    
    iWA_Dump(pkt, iWAmacro_WORLD_PACKET_HEADER_SIZE);

    size = iWA_Net_ReadPacketUint16(pkt);

    return size+4;
}

static void decrypt_world_packet(iWAuint8 *pkt, iWAuint32 len)
{
    iWAuint32 t;
    iWAuint8 x;

    iWA_Log("decrypt_world_packet()");

    if(pkt == NULL || len < iWAmacro_WORLD_PACKET_HEADER_SIZE)   return;

    iWA_Dump(pkt, iWAmacro_WORLD_PACKET_HEADER_SIZE);

    if(world_session_info_block.do_crypto)
    {
        for(t = 0; t < iWAmacro_WORLD_PACKET_HEADER_SIZE; t++)
        {
            world_session_info_block.recv_i %= world_session_info_block.key_size;
            x = (pkt[t] - world_session_info_block.recv_j) ^ world_session_info_block.key[world_session_info_block.recv_i];
            ++world_session_info_block.recv_i;
            world_session_info_block.recv_j = pkt[t];
            pkt[t] = x;
        }
    }
    
    iWA_Dump(pkt, iWAmacro_WORLD_PACKET_HEADER_SIZE);
}


static void handle_auth_challenge_server_packet(void)
{
    IWAserverGame__AuthChallengeServer *chanllenge;
    iWAuint8 *p = world_session_info_block.packet;
    iWAuint16 len;

    iWAuint32 server_seed;
    BIGNUM  cs;
    iWAuint8 buf[4];
    SHA1Context *sha_ctx;

    iWA_Log("handle_auth_challenge_server_packet()");

    len = iWA_Net_ReadPacketUint16(p);
    chanllenge = i_waserver_game__auth_challenge_server__unpack(NULL, len, p+4);
    server_seed = chanllenge->seed;
    i_waserver_game__auth_challenge_server__free_unpacked(chanllenge, NULL);
    
    BN_init(&cs);
    BN_rand(&cs, 4*8, 0, 1);
    iWA_Net_WritePacketBigNumber(buf, &cs);
    world_session_info_block.client_seed = iWA_Net_ReadPacketUint32(buf);
    BN_free(&cs);

    sha_ctx = (SHA1Context*)iWA_Malloc(sizeof(SHA1Context));
    if(sha_ctx == NULL)  return;

    SHA1Reset(sha_ctx);
    SHA1Input(sha_ctx, world_session_info_block.username, iWA_Std_strlen(world_session_info_block.username));  
    iWA_Crypto_Sha1InputUint32(sha_ctx, 0);  /* input t=0 */
    iWA_Crypto_Sha1InputUint32(sha_ctx, world_session_info_block.client_seed);  
    iWA_Crypto_Sha1InputUint32(sha_ctx, server_seed);  
    iWA_Crypto_Sha1InputBigNumber(sha_ctx, &world_session_info_block.K);  
    iWA_Crypto_Sha1ResultBigNumber(sha_ctx, &world_session_info_block.D);

    iWA_Free((iWAuint8*)sha_ctx);
}

static void handle_auth_response_server_packet(void)
{
    IWAserverGame__AuthResponseServer *response;
    iWAuint8 *p = world_session_info_block.packet;
    iWAuint16 len;
    iWAint32 result, status;

    iWA_Log("handle_smsg_auth_response_packet()");

    len = iWA_Net_ReadPacketUint16(p);
    response = i_waserver_game__auth_response_server__unpack(NULL, len, p+4);
    result = response->result;
    i_waserver_game__auth_response_server__free_unpacked(response, NULL);

    if(result == I_WASERVER_GAME__RESULT_CODE__SUCCESS)
    {
        iWA_Log("auth ok");

        status = iWAenum_WORLD_STATUS_OK;
        world_session_info_block.do_crypto = 1;
    }
    else
    {
        iWA_Log("auth failed, code 0x%02x", result);

        /* close seesion */
        disable_world_seesion();
        iWA_Socket_DeinitSession();

        status = iWAenum_WORLD_STATUS_FAIL;
        world_session_info_block.do_crypto = 0;
    }

    /* send msg */
    if(world_session_info_block.func_msg_cb != NULL)    
        ((iWApfunc_World_WorldMsgCb)world_session_info_block.func_msg_cb)(iWAenum_WORLD_MSG_AUTH, status, NULL);
    
}


static void handle_char_enum_server_packet(void)
{
    IWAserverGame__CharEnumServer *char_enum;
    IWAserverGame__Character *chr;
    iWAuint8 *p = world_session_info_block.packet;
    iWAuint16 len;
    iWAuint8 i;
    iWAstruct_Character  *character;

    iWA_Log("handle_char_enum_server_packet()");

    len = iWA_Net_ReadPacketUint16(p);
    char_enum = i_waserver_game__char_enum_server__unpack(NULL, len, p+4);
    world_session_info_block.character_num = char_enum->char_num;

    iWA_Log("character number : %d", world_session_info_block.character_num);


    for(i = 0; i < world_session_info_block.character_num; i++)
    {
        chr = char_enum->characters[i];
        character = &world_session_info_block.character[i];
    
        character->cid = chr->cid;
        iWA_Std_strcpy(character->name, chr->name);
        character->race = chr->race;
        character->grade = chr->grade;
        character->nation = chr->nation;

        iWA_Log("character<%d> name:%s, grade:%d, race:%d, nation:%d", i+1, character->name, character->grade, character->race, character->nation);
    }

    i_waserver_game__char_enum_server__free_unpacked(char_enum, NULL);
    
    /* send msg */
    if(world_session_info_block.func_msg_cb != NULL)    
        ((iWApfunc_World_WorldMsgCb)world_session_info_block.func_msg_cb)(iWAenum_WORLD_MSG_CHAR_ENUM, world_session_info_block.character_num, &world_session_info_block.character[0]);
    
}


static void handle_char_create_server_packet(void)
{
    IWAserverGame__CharCreateServer *response;
    iWAuint8 *p = world_session_info_block.packet;
    iWAuint16 len;
    iWAint32 status;

    iWA_Log("handle_char_create_server_packet()");

    len = iWA_Net_ReadPacketUint16(p);
    response = i_waserver_game__char_create_server__unpack(NULL, len, p+4);
    if(response->result == I_WASERVER_GAME__RESULT_CODE__SUCCESS)
    {
        world_session_info_block.character[0].cid = response->cid;
        iWA_Log("character create ok");
        status = iWAenum_WORLD_STATUS_OK;
    }
    else
    {
        iWA_Log("character create failed, 0x%02x", response->result);
        
        status = iWAenum_WORLD_STATUS_FAIL;

        /* close seesion */
        disable_world_seesion();
        iWA_Socket_DeinitSession();    
    }
    
    i_waserver_game__char_create_server__free_unpacked(response, NULL);

    /* send msg */
    if(world_session_info_block.func_msg_cb != NULL)    
        ((iWApfunc_World_WorldMsgCb)world_session_info_block.func_msg_cb)(iWAenum_WORLD_MSG_CHAR_CREATE, status, NULL);
}

static void handle_char_delete_server_packet(void)
{
    IWAserverGame__CharDeleteServer *response;
    iWAuint8 *p = world_session_info_block.packet;
    iWAuint16 len;
    iWAint32 status;

    iWA_Log("handle_char_delete_server_packet()");

    len = iWA_Net_ReadPacketUint16(p);
    response = i_waserver_game__char_delete_server__unpack(NULL, len, p+4);
    if(response->result == I_WASERVER_GAME__RESULT_CODE__SUCCESS)
    {
        iWA_Log("character delete ok");
        status = iWAenum_WORLD_STATUS_OK;
    }
    else
    {
        iWA_Log("character delete failed, 0x%02x", response->result);
        
        status = iWAenum_WORLD_STATUS_FAIL;

        /* close seesion */
        disable_world_seesion();
        iWA_Socket_DeinitSession();    
    }
    
    i_waserver_game__char_delete_server__free_unpacked(response, NULL);

    /* send msg */
    if(world_session_info_block.func_msg_cb != NULL)    
        ((iWApfunc_World_WorldMsgCb)world_session_info_block.func_msg_cb)(iWAenum_WORLD_MSG_CHAR_DELETE, status, NULL);
}


static iWAbool write_auth_session_client_packet(void)
{
    IWAserverGame__AuthSessionClient sess;
    iWAuint8 *p = world_session_info_block.packet;
    iWAuint8   D[SHA1HashSize+1];              


    iWA_Log("write_auth_session_client_packet()");

    i_waserver_game__auth_session_client__init(&sess);
    sess.build = iWA_Auth_GetClientBuild();
    sess.username = world_session_info_block.username;
    sess.seed = world_session_info_block.client_seed;

    iWA_Net_WritePacketBigNumber(D, &world_session_info_block.D);
    sess.d.data = D;
    sess.d.len = SHA1HashSize;

    world_session_info_block.packet_len = i_waserver_game__auth_session_client__pack(&sess, p+4) + 4;
    write_client_packet_header(p, world_session_info_block.packet_len - 4, iWAenum_GAME_CMD_AUTH_SEESION);

    return 1;
}


static iWAbool write_char_enum_client_packet(void)
{
    IWAserverGame__CharEnumClient char_enum;
    iWAuint8 *p = world_session_info_block.packet;

    iWA_Log("write_char_enum_client_packet()");

    i_waserver_game__char_enum_client__init(&char_enum);

    world_session_info_block.packet_len = i_waserver_game__char_enum_client__pack(&char_enum, p+4) + 4;
    write_client_packet_header(p, world_session_info_block.packet_len - 4, iWAenum_GAME_CMD_CHAR_ENUM);

    return 1;
}


static iWAbool write_player_login_client_packet(void)
{
    IWAserverGame__PlayerLoginClient player_login;
    iWAuint8 *p = world_session_info_block.packet;

    iWA_Log("write_player_login_client_packet()");

    i_waserver_game__player_login_client__init(&player_login);
    player_login.cid = world_session_info_block.character[0].cid;

    world_session_info_block.packet_len = i_waserver_game__player_login_client__pack(&player_login, p+4) + 4;
    write_client_packet_header(p, world_session_info_block.packet_len - 4, iWAenum_GAME_CMD_PLAYER_LOGIN);

    return 1;
}

static iWAbool write_char_create_client_packet(void)
{
    IWAserverGame__CharCreateClient char_create;
    iWAuint8 *p = world_session_info_block.packet;
    iWAstruct_Character  *character = &world_session_info_block.character[0];

    iWA_Log("write_char_create_client_packet()");

    i_waserver_game__char_create_client__init(&char_create);
    char_create.name = character->name;
    char_create.nation = character->nation;
    char_create.race = character->race;

    world_session_info_block.packet_len = i_waserver_game__char_create_client__pack(&char_create, p+4) + 4;
    write_client_packet_header(p, world_session_info_block.packet_len - 4, iWAenum_GAME_CMD_CHAR_CREATE);

    return 1;
}

static iWAbool write_char_delete_client_packet(void)
{
    IWAserverGame__CharDeleteClient char_delete;
    iWAuint8 *p = world_session_info_block.packet;

    iWA_Log("write_char_delete_client_packet()");

    i_waserver_game__char_delete_client__init(&char_delete);
    char_delete.cid = world_session_info_block.character[0].cid;

    world_session_info_block.packet_len = i_waserver_game__char_delete_client__pack(&char_delete, p+4) + 4;
    write_client_packet_header(p, world_session_info_block.packet_len - 4, iWAenum_GAME_CMD_CHAR_DELETE);

    return 1;
}


void iWA_World_Init(void)
{
    iWA_Log("iWA_World_Init()");

    iWA_Std_memset((void*)&world_session_info_block, 0, sizeof(iWAstruct_World_SessionInfoBlock));

#if 0
    iWA_Std_strcpy(world_session_info_block.username, iWA_Auth_GetUsername());

    BN_copy(&world_session_info_block.K, iWA_Auth_GetK());
#else
    {
    BIGNUM *I = &world_session_info_block.K;;
    iWA_Std_strcpy(world_session_info_block.username, "LOUHAO3");
    BN_init(I);
    BN_hex2bn(&I, "D10FDB0FB4FDC4893290764BEDE4500631EB2E3FCCBDE656A710E8A6FA6736933E9C63562D895729");
    }
#endif
    
    BN_init(&world_session_info_block.D);

    world_session_info_block.key_size = iWA_Net_WritePacketBigNumber(world_session_info_block.key, &world_session_info_block.K);
}

void iWA_World_Deinit(void)
{
    iWA_Log("iWA_World_Deinit()");

    BN_free(&world_session_info_block.K);
    BN_free(&world_session_info_block.D);

    iWA_Std_memset((void*)&world_session_info_block, 0, sizeof(iWAstruct_World_SessionInfoBlock));
}

void iWA_World_DoReceive(void)
{
    if(receive_world_packet())   handle_world_packet();
}

iWAbool iWA_World_Start(iWAuint8 *server, iWAuint16 port, void *msg_cb)
{
    iWA_Log("iWA_World_Start()");

    if(server == NULL)  return 0;

    world_session_info_block.func_msg_cb = msg_cb;

    if(!iWA_Socket_InitSession(server, port, 1024, 1024, (void*)split_world_packet, 4, (void*)decrypt_world_packet))    return 0;
    
    enable_world_seesion();

    return 1;    
}


iWAbool iWA_World_GetCharEnum(void)
{
    iWA_Log("iWA_World_GetCharEnum()");

    write_char_enum_client_packet();
    send_world_packet();

    return 1;
}

iWAbool iWA_World_CreateChar(iWAuint8 *name, iWAuint8 race, iWAuint8 nation)
{
    iWAstruct_Character  *character = &world_session_info_block.character[0];

    iWA_Log("iWA_World_CreateChar()");

    if(name == NULL)    return 0;

    iWA_Std_strcpy(character->name, name);
    character->race = race;
    character->nation = nation;
    character->grade = 1;

    write_char_create_client_packet();
    send_world_packet();

    return 1;
}

iWAbool iWA_World_DeleteChar(iWAuint32 cid)
{

    iWA_Log("iWA_World_DeleteChar()");


    world_session_info_block.character[0].cid = cid;

    write_char_delete_client_packet();
    send_world_packet();

    return 1;
}



iWAbool iWA_World_Login(iWAuint32 cid)
{
    iWA_Log("iWA_World_Login()");

    world_session_info_block.character[0].cid = cid;

    write_player_login_client_packet();
    send_world_packet();

    return 1;
}


/****************************  iWA_World_Start()  usage sample ***********************************/

static void world_msg_callback(iWAuint32 msg, iWAint32 para1, void *para2)
{
    iWAuint32 i;
    iWAstruct_Character  *character;

    iWA_Log("world_msg_callback msg: 0x%02x", msg);

    switch(msg)
    {
        case iWAenum_WORLD_MSG_AUTH:
            if(para1 == iWAenum_WORLD_STATUS_OK)
            {
                iWA_Log("Pass Auth, Start Getting Character List");
                iWA_World_GetCharEnum();
            }
            else
            {
                iWA_Log("Game Server Auth Fail");    
            }
            break;

        case iWAenum_WORLD_MSG_CHAR_ENUM:
            iWA_Log("Character Num : %d", para1);
            for(i = 0, character = (iWAstruct_Character*)para2; i < para1; i++)
            {
                iWA_Log("character<%d> name:%s, grade:%d, race:%d, nation:%d", i+1, character[i].name, character[i].grade, character[i].race, character[i].nation);
            }
            if(para1 == 0)
            {
                iWA_Log("Creating Character");
                iWA_World_CreateChar("lly", iWAenum_CHARACTER_RACE_GUISHA, iWAenum_CHARACTER_NATION_WUCHEN);
            }
            else
            {
                iWA_Log("Character %s Login", character[0].name);
                //iWA_World_Login(character[0].guid);
                iWA_World_DeleteChar(character[0].cid);
            }
            break;
            
        case iWAenum_WORLD_MSG_CHAR_CREATE:
            if(para1 == iWAenum_WORLD_STATUS_OK)
            {
                iWA_Log("Create Character OK, Refreshing Character List");
                iWA_World_GetCharEnum();
            }
            else
            {
                iWA_Log("Create Character Fail");    
            }
            break;

        case iWAenum_WORLD_MSG_CHAR_DELETE:
            if(para1 == iWAenum_WORLD_STATUS_OK)
            {
                iWA_Log("Delete Character OK");
            }
            else
            {
                iWA_Log("Delete Character Fail");    
            }
            break;
            
    }
}


iWAbool iWA_World_StartSample(iWAuint8 *server, iWAuint16 port)
{
    return iWA_World_Start(server, port, (void*)world_msg_callback);
}








