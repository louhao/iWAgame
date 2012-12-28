
#include "iWA.h"


#ifdef WIN32
	#include <winsock.h>
#else
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
#endif


#define iWAmacro_SOCKET_RECV_TIMEOUT                 (1)             /* 1s */
#define iWAmacro_SOCKET_SEND_SEGMENT_SIZE        (1024)
#define iWAmacro_SOCKET_SPLIT_HEADER_SIZE_MIN      (1)



typedef iWAuint32 (*iWApfunc_Socket_SplitPacket)(iWAuint8*, iWAuint32);
typedef void (*iWApfunc_Socket_DecryptPacket)(iWAuint8*, iWAuint32);

typedef struct
{
    void *next;
    iWAuint32 len;
    iWAuint32 valid;
}iWAstruct_Socket_PacketHeader;


typedef struct
{
    iWAuint8 *send_buf;         /* a ring buffer */
    iWAuint32 send_buf_size;
    iWAuint8 *send_data_head;
    iWAuint32 send_data_len;

    iWAuint8 *recv_buf;         /* a ring buffer */
    iWAuint32 recv_buf_size;
    iWAuint8 *recv_data_head;
    iWAuint32 recv_data_len;

    iWAstruct_Socket_PacketHeader   *send_queue;
    iWAstruct_Socket_PacketHeader   *recv_queue;

    pthread_t  session_thread;

    void *func_split_packet;
    void *func_decrypt_packet;
    iWAuint32 split_header_size;
    
    iWAuint8  ip[16];
    iWAuint16 port;
    
    iWAuint16 valid;        /* seesion valid flag */
}iWAstruct_Socket_SessionInfoBlock;



static iWAstruct_Socket_SessionInfoBlock   session_info_block = {0};

static pthread_mutex_t  mutex_send_queue;
static pthread_mutex_t  mutex_recv_queue;


static iWAbool write_to_send_buf(iWAuint8 *data, iWAint32 len)
{
    iWAuint8 *partI = NULL, *partII = NULL;
    iWAint32 partI_size, partII_size;
    iWAuint8 *p;
    iWAuint32 l;
    
    if(len == 0)  return 1;

    /* check buf space */
    if(len > (iWAint32)(session_info_block.send_buf_size - session_info_block.send_data_len))  return 0;

    /* calculate partI */
    partI_size = (session_info_block.send_buf + session_info_block.send_buf_size) - (session_info_block.send_data_head + session_info_block.send_data_len);
    if(partI_size > 0)
        partI = session_info_block.send_data_head + session_info_block.send_data_len;
    else
        partI_size = 0;

    /* calculate partII */
    partII_size = session_info_block.send_buf_size - session_info_block.send_data_len - partI_size;
    if(partII_size > 0)
        partII = session_info_block.send_data_head - partII_size;

    /* write partI if exists */
    if(partI_size > 0)   
    {
        l = partI_size > len ? len : partI_size;
    
        iWA_Std_memcpy(partI, data, l);
        p = data + l;
        l = len - l;
    }
    else
    {
        p = data;
        l = len;
    }

    /* if data retains, write to partII */
    if(partII_size > 0 && l > 0)   
    {
        iWA_Std_memcpy(partII, p, l);
    }

    return 1;
}

static iWAbool read_from_recv_buf(iWAuint8 *data, iWAuint32 len)
{
    iWAuint32 partI_len;

    if(len > session_info_block.recv_data_len)  return 0;

    /* calculate partI */
    partI_len = session_info_block.recv_buf + session_info_block.recv_buf_size - session_info_block.recv_data_head;
    if(partI_len > session_info_block.recv_data_len)    partI_len = session_info_block.recv_data_len;

    /* read partI */
    iWA_Std_memcpy(data, session_info_block.recv_data_head, len>partI_len?partI_len:len);

    /* read partII if need */
    if(len>partI_len)   iWA_Std_memcpy(data+partI_len, session_info_block.recv_buf, len-partI_len);

    return 1;
}

static void* session_thread(void *data)
{    
    iWAint32 ret, sock;
    struct sockaddr_in addr;
    iWAstruct_Socket_PacketHeader *pkt, *pkt_pro;
    iWAint32 send_partI_len,  send_partII_len, send_len;
    iWAint32 recv_partI_size, recv_partII_size;
    iWAuint8 *split_header;

#ifdef WIN32
    iWAint32 timeout = iWAmacro_SOCKET_RECV_TIMEOUT*1000;
#else
    struct timeval timeout={iWAmacro_SOCKET_RECV_TIMEOUT, 0};   
#endif

#ifdef WIN32
    WSADATA wsa;
    iWAuint16 version = ((iWAuint16)2) | ((iWAuint16)(0 << 8));
    
    ret = WSAStartup(version, &wsa);
    if (ret != 0)       return 0;
#endif

    iWA_Log("iWA_Socket.c session_thread start");

    /* create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)     
    {
        iWA_Log("socket create fail");
        return 0;
    }
    
    /* set recv timeout */
#ifdef WIN32
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (iWAint8*)&timeout, sizeof(iWAint32));
#else
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif
    if(ret == -1)    
    {
        iWA_Log("setsockopt fail");
        return 0;
    }

    /* connect server */
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(session_info_block.ip);
    addr.sin_port = htons(session_info_block.port);
    ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if(ret == -1)  
    {
        iWA_Log("socket connect fail");
        return 0;
    }

    /* split header buf */
    split_header = iWA_Malloc(session_info_block.split_header_size);
    if(split_header == NULL)    return 0;

    while(session_info_block.valid)
    {
    //    pthread_testcancel();
    
        /* write packet in send queue to send buf */
        pthread_mutex_lock(&mutex_send_queue);
        while((pkt = session_info_block.send_queue) != NULL)
        {
            if(write_to_send_buf((iWAuint8*)pkt+sizeof(iWAstruct_Socket_PacketHeader), pkt->len))
            {
                session_info_block.send_data_len += pkt->len;
                pkt->valid = 0;
            }
            
            if(pkt->valid)   break;  /* send buf is full, can't contain more packet */

            session_info_block.send_queue = (iWAstruct_Socket_PacketHeader*)pkt->next;
            iWA_Free(pkt);
        }
        pthread_mutex_unlock(&mutex_send_queue);

        /* send data in send buf part I*/
        if(session_info_block.send_data_len > 0)
        {
            /* calculate send buf part I len */
            if(session_info_block.send_data_head + session_info_block.send_data_len > session_info_block.send_buf + session_info_block.send_buf_size)
                send_partI_len = session_info_block.send_buf + session_info_block.send_buf_size - session_info_block.send_data_head;
            else
                send_partI_len = session_info_block.send_data_len;
        
            while(send_partI_len > 0)
            {
                /* only send iWAmacro_SOCKET_SEND_SEGMENT_SIZE byts in once send() call, avoid send() internal buffer too small */
                send_len = send_partI_len > iWAmacro_SOCKET_SEND_SEGMENT_SIZE ? iWAmacro_SOCKET_SEND_SEGMENT_SIZE : send_partI_len;

                /* call send() */
                ret = send(sock, session_info_block.send_buf, send_len, 0);

                /* send fail */
                if(ret <= 0)    break;

                /* adjust send buf */
                send_partI_len -= ret;
                session_info_block.send_data_len -= ret;
                if(send_partI_len == 0)
                    session_info_block.send_data_head = session_info_block.send_buf;
                else
                    session_info_block.send_data_head += ret;
            }
        }

        /* send send buf part II if have data */
        if(session_info_block.send_data_head == session_info_block.send_buf)
        {
            send_partII_len = session_info_block.send_data_len;

            while(send_partII_len > 0)
            {
                /* only send iWAmacro_SOCKET_SEND_SEGMENT_SIZE byts in once send() call, avoid send() internal buffer too small */
                send_len = send_partII_len > iWAmacro_SOCKET_SEND_SEGMENT_SIZE ? iWAmacro_SOCKET_SEND_SEGMENT_SIZE : send_partII_len;

                /* call send() */
                ret = send(sock, session_info_block.send_data_head, send_len, 0);

                /* send fail */
                if(ret <= 0)    break;

                /* adjust send buf */
                send_partII_len -= ret;
                session_info_block.send_data_len -= ret;
                if(session_info_block.send_data_len == 0)
                    session_info_block.send_data_head = session_info_block.send_buf;
                else
                    session_info_block.send_data_head += ret;
            }
        }

            
        /* clear invalid recv packet */
        pthread_mutex_lock(&mutex_recv_queue);
        pkt_pro = NULL;
        pkt = session_info_block.recv_queue;
        while(pkt != NULL)
        {
            if(!pkt->valid)     /* packet data already been handled, release packet */
            {
                if(pkt == session_info_block.recv_queue)
                {
                    session_info_block.recv_queue = (iWAstruct_Socket_PacketHeader*)pkt->next;
                    iWA_Free(pkt);
                    pkt = session_info_block.recv_queue;
                }
                else
                {
                    pkt_pro->next = pkt->next;
                    iWA_Free(pkt);
                    pkt = (iWAstruct_Socket_PacketHeader*)pkt_pro->next;                    
                }
            }
            else
            {
                pkt_pro = pkt;
                pkt = (iWAstruct_Socket_PacketHeader*)pkt->next;
            }    
        }
        pthread_mutex_unlock(&mutex_recv_queue);

        /* receive data to recv buf part I */
        if(session_info_block.recv_data_len < session_info_block.recv_buf_size)
        {
            /* calculate partI size */
            recv_partI_size = (session_info_block.recv_buf + session_info_block.recv_buf_size) - (session_info_block.recv_data_head + session_info_block.recv_data_len);

            /* receive */
            if(recv_partI_size > 0)
            {
                ret = recv(sock, session_info_block.recv_data_head + session_info_block.recv_data_len, recv_partI_size, 0);

                /* adjust recv buf */
                if(ret > 0)
                {
                    session_info_block.recv_data_len += ret;
                    recv_partI_size -= ret;
                }
            }
        }

        /* if partI is full, try to receive to buf part II*/
        if(session_info_block.recv_data_len < session_info_block.recv_buf_size && recv_partI_size <= 0)
        {
            /* calculate partII size */
            recv_partII_size = session_info_block.recv_buf_size - session_info_block.recv_data_len;

            /* receive */
            if(recv_partII_size > 0)
            {
                ret = recv(sock, session_info_block.recv_data_head - recv_partII_size, recv_partII_size, 0);

                /* adjust recv buf */
                if(ret > 0)   session_info_block.recv_data_len += ret;
            }
        }
        
        /* split packet from recv buf */
        while(read_from_recv_buf(split_header, session_info_block.split_header_size))
        {
            /* analyze header */
            ret = ((iWApfunc_Socket_SplitPacket)session_info_block.func_split_packet)(split_header, session_info_block.split_header_size);

            /* entire packet already been received */
            if(ret > 0 && session_info_block.recv_data_len >= (iWAuint32)ret)
            {
                /* read data to packet */
                pkt = iWA_Malloc(ret + sizeof(iWAstruct_Socket_PacketHeader));
                if(pkt == NULL)  break;
                pkt->next = NULL;
                pkt->len = ret;
                pkt->valid = 1;
                read_from_recv_buf((iWAuint8*)pkt + sizeof(iWAstruct_Socket_PacketHeader), ret);

                /* if need, decrypt packet */
                if(session_info_block.func_decrypt_packet != NULL)   
                    ((iWApfunc_Socket_DecryptPacket)session_info_block.func_decrypt_packet)((iWAuint8*)pkt + sizeof(iWAstruct_Socket_PacketHeader), ret);
                    
                /* add packet to queue */
                pthread_mutex_lock(&mutex_recv_queue);
                if(session_info_block.recv_queue == NULL)
                {
                    session_info_block.recv_queue = pkt;
                }
                else
                {
                    pkt_pro = session_info_block.recv_queue;
                    while(pkt_pro->next != NULL)    pkt_pro = (iWAstruct_Socket_PacketHeader*)pkt_pro->next;
                    pkt_pro->next = (void*)pkt;
                }
                pthread_mutex_unlock(&mutex_recv_queue);

                /* adjust recv buf */
                session_info_block.recv_data_len -= ret;
                if(session_info_block.recv_data_len == 0)
                {
                    session_info_block.recv_data_head = session_info_block.recv_buf;
                }
                else
                {
                    session_info_block.recv_data_head += ret;
                    if(session_info_block.recv_data_head > session_info_block.recv_buf + session_info_block.recv_buf_size)
                        session_info_block.recv_data_head -= session_info_block.recv_buf_size;
                }
            }
            else
            {
                break;
            }
        }
    }

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    iWA_Log("socket session end");

    iWA_Free(split_header);
    pthread_exit(NULL);
    
    return 0;
}


iWAbool iWA_Socket_InitSession(iWAuint8 *ip, iWAuint16 port, iWAuint32 send_buf_size, iWAuint32 recv_buf_size, void *func_split, iWAuint32 split_size, void *func_decrypt)
{
    if(ip == NULL || func_split == NULL)  return 0;

    iWA_Std_memset(&session_info_block, 0, sizeof(iWAstruct_Socket_SessionInfoBlock));

    session_info_block.send_buf = iWA_Malloc(send_buf_size);
    if(session_info_block.send_buf == NULL)     return 0;
    session_info_block.send_buf_size = send_buf_size;
    session_info_block.send_data_head = session_info_block.send_buf;

    session_info_block.recv_buf = iWA_Malloc(recv_buf_size);
    if(session_info_block.recv_buf == NULL)     return 0;
    session_info_block.recv_buf_size = recv_buf_size;
    session_info_block.recv_data_head = session_info_block.recv_buf;

    session_info_block.func_split_packet = func_split;
    session_info_block.split_header_size = split_size < iWAmacro_SOCKET_SPLIT_HEADER_SIZE_MIN ? iWAmacro_SOCKET_SPLIT_HEADER_SIZE_MIN : split_size;
    session_info_block.func_decrypt_packet = func_decrypt;

    iWA_Std_strcpy(session_info_block.ip, ip);
    session_info_block.port = port;

    pthread_mutex_init(&mutex_send_queue, NULL);
    pthread_mutex_init(&mutex_recv_queue, NULL);

    session_info_block.valid = 1;

    pthread_create(&session_info_block.session_thread, NULL, session_thread, NULL);
    //pthread_detach(session_info_block.session_thread);    

    return 1;
}

void iWA_Socket_DeinitSession(void)
{
    iWAstruct_Socket_PacketHeader *pkt, *pkt_next;
    void *ret_val;

    session_info_block.valid = 0;

    //pthread_cancel(session_info_block.session_thread);
  
    pthread_join(session_info_block.session_thread, &ret_val);
    
    if(session_info_block.send_buf != NULL)     iWA_Free(session_info_block.send_buf);
    
    if(session_info_block.recv_buf != NULL)     iWA_Free(session_info_block.recv_buf);

    pthread_mutex_lock(&mutex_send_queue);
    pkt = session_info_block.send_queue;
    while(pkt != NULL)
    {
        pkt_next = (iWAstruct_Socket_PacketHeader*)pkt->next;
        iWA_Free(pkt);
        pkt = pkt_next;
    }
    pthread_mutex_unlock(&mutex_send_queue);

    pthread_mutex_lock(&mutex_recv_queue);
    pkt = session_info_block.recv_queue;
    while(pkt != NULL)
    {
        pkt_next = (iWAstruct_Socket_PacketHeader*)pkt->next;
        iWA_Free(pkt);
        pkt = pkt_next;
    }
    pthread_mutex_unlock(&mutex_recv_queue);

    pthread_mutex_destroy(&mutex_send_queue);
    pthread_mutex_destroy(&mutex_recv_queue);
}


iWAbool iWA_Socket_SendPacket(iWAuint8 *data, iWAuint32 len)
{
    iWAstruct_Socket_PacketHeader *pkt, *pkt_end;

    iWA_Log("iWA_Socket_SendPacket()");

    if(!session_info_block.valid)   return 0;

    pkt = iWA_Malloc(len + sizeof(iWAstruct_Socket_PacketHeader));
    if(pkt == NULL)  return 0;

    /* fill pkt */
    pkt->next = NULL;
    pkt->len = len;
    pkt->valid = 1;
    iWA_Std_memcpy((iWAuint8*)pkt + sizeof(iWAstruct_Socket_PacketHeader), data, len);

    /* add pkt to send queue */
    pthread_mutex_lock(&mutex_send_queue);
    if(session_info_block.send_queue == NULL)
    {
        session_info_block.send_queue = pkt;
    }
    else
    {
        pkt_end = session_info_block.send_queue;
        while(pkt_end->next != NULL)    pkt_end = (iWAstruct_Socket_PacketHeader*)pkt_end->next;
        pkt_end->next = (void*)pkt;
    }    
    pthread_mutex_unlock(&mutex_send_queue);

    return 1;
}

iWAbool iWA_Socket_ReceivePacket(iWAuint8 *data, iWAuint32 *len)
{
    iWAstruct_Socket_PacketHeader *pkt;

    if(!session_info_block.valid)   return 0;

    pthread_mutex_lock(&mutex_recv_queue);
    pkt = session_info_block.recv_queue;
    while(pkt != NULL)
    {
        if(pkt->valid)
        {
            memcpy(data, (iWAuint8*)pkt + sizeof(iWAstruct_Socket_PacketHeader), pkt->len);
            *len = pkt->len;
            pkt->valid = 0;
            
            break;
        }

        pkt = (iWAstruct_Socket_PacketHeader*)pkt->next;
    }
    pthread_mutex_unlock(&mutex_recv_queue);

    return pkt == NULL ? 0 : 1;
}


iWAbool iWA_Socket_ReceivePacket2(iWAuint8 **data, iWAuint32 *len, iWAuint32 **valid)
{
    iWAstruct_Socket_PacketHeader *pkt;

    if(!session_info_block.valid)   return 0;

    pthread_mutex_lock(&mutex_recv_queue);
    pkt = session_info_block.recv_queue;
    while(pkt != NULL)
    {
        if(pkt->valid)
        {
            *data = (iWAuint8*)pkt + sizeof(iWAstruct_Socket_PacketHeader);
            *len = pkt->len;
            *valid = &(pkt->valid);
            
            break;
        }

        pkt = (iWAstruct_Socket_PacketHeader*)pkt->next;
    }
    pthread_mutex_unlock(&mutex_recv_queue);

    return pkt == NULL ? 0 : 1;
}


