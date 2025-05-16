
/*
 * transport.c
 *
 * COS461: HW#3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */
/*
th_seq	tcp_seq	与数据包相关的序列号
th_ack	tcp_seq	ACK数据包的ack值
th_off	4 bits	数据包中数据起始位置的偏移量，单位为32bit的字
th_flags	uint8_t	各种控制位，如TH_FIN, TH_SYN等
th_win	uint16_t	接收方窗口大小的字节数，如发送数据包的主机愿意接受的未完成数据量。
发送方窗口大小由另一方通告的接收方窗口和拥塞窗口中的最小值所决定。
请注意，接收到的数据可能会越过当前接收方窗口的两端。在这种情况下，数据将被分为两部分，每一部分都需经过适当处理。
所发送数据不要超出发送方的窗口值。
所有窗口的第一个字节始终是最后一个确认数据的字节。
例如，对于接收方窗口，如果最后一次确认的序列号是8192，则接收方愿意接受序列号8192到11263（8192 + 3072-1）的数据。
*/
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>  //字节序转换
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#define min(a, b) ((a) < (b) ? (a) : (b))
const int MAX_HEADER = 536;
const int WIND_SIZE = 3072;
enum stcp_states
{
    CSTATE_ESTABLISHED,
    SYN_SENT,
    SYN_ACK_RECEIVED,
    SYN_RECEIVED,
    SYN_ACK_SENT,
    CSTATE_CLOSED,
    FIN_SEND,
    NIL
} ; /* obviously you should have more states */

/* this structure is global to a mysocket descriptor */
// context_t
typedef struct
{
    bool_t done; /* TRUE once connection is closed */

    int connection_state; /* state of the connection (established, etc.) */
    tcp_seq seq_num;
    tcp_seq recv_seq_num;
    unsigned int recv_wind_size;

    /* any other connection-wide global variables go here */
} context_t; // 上下文

typedef struct
{
    char *buf;
    int len;
    int seq;
} buffer;
buffer *recvbuff, sendbuff;
static void
generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
bool send_syn(mysocket_t sd, context_t *ctx);
void wait_for_syn_ack(mysocket_t sd, context_t *ctx);
bool send_ack(mysocket_t sd, context_t *ctx);
STCPHeader* create_syn_ack_packet(unsigned int seq, unsigned int ack);
bool send_fin(mysocket_t sd, context_t *ctx);
STCPHeader *create_fin_packet(unsigned int seq, unsigned int ack);
void wait_for_syn(mysocket_t sd, context_t *ctx);
bool send_ack_syn(mysocket_t sd, context_t *ctx);
STCPHeader *create_syn_packet(unsigned int seq, unsigned int ack);
void send_app_data(context_t *ctx, mysocket_t sd);
void recv_app_data(context_t *ctx, mysocket_t sd);
void app_close(context_t *ctx, mysocket_t sd);
bool send_appdata_network(mysocket_t sd, context_t *ctx, char *recv_buf, unsigned int recv_size);
bool wait_for_event(mysocket_t sd, context_t *ctx, stcp_event_type_t event, unsigned int flags, enum stcp_states states);
STCPHeader *create_ack_packet(unsigned int seq, unsigned int ack);
void parse_DATA_packet(context_t *ctx, char *buf, bool& isfin);
/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void wait_for_SYN_ACK(mysocket_t sd, context_t* ctx) {
  char buffer[sizeof(STCPHeader)];

  unsigned int event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);

  ssize_t receivedBytes = stcp_network_recv(sd, buffer, MAX_HEADER);

    printf("Received %d bytes\n", receivedBytes);
  // Verify size of received packet
  if (receivedBytes < sizeof(STCPHeader)) {
    free(ctx);
    // stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

  // Parse received data
  STCPHeader* receivedPacket = (STCPHeader*)buffer;
    printf("Received packet with flags: %d\n", receivedPacket->th_flags);
  // Check for appropriate flags and set connection state
  if (receivedPacket->th_flags == (TH_ACK | TH_SYN)) {
    printf("Received SYN-ACK packet\n");
    ctx->recv_seq_num = ntohl(receivedPacket->th_seq);
    ctx->recv_wind_size =
        ntohs(receivedPacket->th_win) > 0 ? ntohs(receivedPacket->th_win) : 1;
    ctx->connection_state = SYN_ACK_RECEIVED;
  }
}
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *)calloc(1, sizeof(context_t));
    printf("ctx-done: %d\n", ctx->done);
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    if (is_active)
    {
        printf("send syn\n");
        // send a syn packet
        if (!send_syn(sd, ctx))
            return;
        printf("wait for syn ack\n");
        wait_for_SYN_ACK(sd, ctx);
        //wait_for_event(sd, ctx, NETWORK_DATA, TH_ACK | TH_SYN, SYN_ACK_RECEIVED); // 等待ack和syn的包
        if (!send_ack(sd, ctx))
            return;
    }
    else
    {
         printf("wait for syn\n");
        // wait arrive
        wait_for_event(sd, ctx, NETWORK_DATA, TH_SYN, SYN_RECEIVED); // 等待syn的包
        if (!send_ack_syn(sd, ctx))
            return;
        wait_for_event(sd, ctx, NETWORK_DATA, TH_ACK, CSTATE_ESTABLISHED);
    }
    ctx->connection_state = CSTATE_ESTABLISHED; // 建立了连接
    printf("connection_state: %d\n", ctx->connection_state);
    // 判断连接是否成功 如果失败要set errno
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    //free(ctx);？？？
}

/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

    const int MAX = 255;
#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->seq_num = 1;
#else
    /* you have to fill this up */
    /*ctx->initial_sequence_num =;*/
    srand(time(NULL));
    ctx->seq_num = rand() % MAX + 1;
#endif
}

/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    printf("control11 loop\n");
    printf("ctx_done: %d\n", ctx->done);
    while (!ctx->done)
    {
          if (ctx->connection_state == CSTATE_CLOSED) {
            ctx->done = true;
            continue;
            }
        unsigned int event;
        printf("wait for event\n");

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
        printf("event: %d\n", event);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            printf("send app data\n");
            send_app_data(ctx, sd);
        }
        else if (event & NETWORK_DATA)
        {
            // 网络层有数据要传到应用层
            printf("recv app data\n");
            recv_app_data(ctx, sd);
        }
        else if (event & APP_CLOSE_REQUESTED)
        {
            // 断连 发送fin包
            printf("close\n");
            app_close(ctx, sd);
        }

        /* etc. */
    }
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format, ...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}
STCPHeader *create_syn_packet(unsigned int seq, unsigned int ack)
{
    STCPHeader *SYN_packet = (STCPHeader *)malloc(sizeof(STCPHeader));
    SYN_packet->th_seq = htonl(seq);
    SYN_packet->th_ack = htonl(ack);
    SYN_packet->th_off = htons(5);         // header size offset for packed data
    SYN_packet->th_flags = TH_SYN;         // set packet type to SYN
    SYN_packet->th_win = htons(WIND_SIZE); // default value
    return SYN_packet;
}
STCPHeader *create_ack_packet(unsigned int seq, unsigned int ack)
{
    STCPHeader *ACK_packet = (STCPHeader *)malloc(sizeof(STCPHeader));
    ACK_packet->th_seq = htonl(seq);
    ACK_packet->th_ack = htonl(ack);
    ACK_packet->th_off = htons(5);         // header size offset for packed data
    ACK_packet->th_flags = TH_ACK;         // set packet type to ACK
    ACK_packet->th_win = htons(WIND_SIZE); // default value
    return ACK_packet;
}
bool send_syn(mysocket_t sd, context_t *ctx)
{
    STCPHeader *stcp_header = create_syn_packet(ctx->seq_num, 0);
    ctx->seq_num++;
    ssize_t sentBytes =
        stcp_network_send(sd, stcp_header, sizeof(STCPHeader), NULL);

    // 检测发送是否成功
    if (sentBytes > 0)
    {

        ctx->connection_state = SYN_SENT;
        free(stcp_header);
        return true;
    }
    else
    {
        free(stcp_header);
        free(ctx);
        ctx = NULL;
        stcp_header = NULL;
        errno = ECONNREFUSED;
        return false;
    }
}

bool wait_for_event(mysocket_t sd, context_t *ctx, stcp_event_type_t event, unsigned int flags, enum stcp_states states)
{
    char buf[sizeof(STCPHeader)];
    unsigned int flag = stcp_wait_for_event(sd, event, NULL);
    ssize_t recvBytes = stcp_network_recv(sd, buf, MAX_HEADER);
    if (recvBytes < sizeof(STCPHeader))
    {
        errno = ECONNREFUSED;
        return false;
    }
    STCPHeader *stcp_header = (STCPHeader *)buf;
    // 判断是不是syn和ack的包
   // printf("th_flags:%d\n", stcp_header->th_flags==flags);
    if (stcp_header->th_flags == flags)
    {
        ctx->recv_seq_num = ntohl(stcp_header->th_seq);
       // printf("th_win:%d", ntohs(stcp_header->th_win));
        ctx->recv_wind_size =
            ntohs(stcp_header->th_win) > 0 ? ntohs(stcp_header->th_win) : 1;
        if (flag == TH_ACK)
        {
            if (ctx->connection_state == FIN_SEND)
            {
                ctx->connection_state = CSTATE_CLOSED;
            }
        }
        else
            ctx->connection_state = states;
    }
}
bool send_ack(mysocket_t sd, context_t *ctx)
{
    STCPHeader *stcp_header = create_ack_packet(ctx->seq_num, ctx->recv_seq_num + 1);
    ssize_t sentBytes =
        stcp_network_send(sd, stcp_header, sizeof(STCPHeader), NULL);

    if (sentBytes > 0)
    {
        free(stcp_header);
        stcp_header = NULL;
        return true;
    }
    else
    {
        free(stcp_header);
        free(ctx);
        stcp_header = NULL;
        ctx = NULL;
        errno = ECONNREFUSED;
        return false;
    }
}

STCPHeader* create_syn_ack_packet(unsigned int seq, unsigned int ack) {
  STCPHeader* SYN_ACK_packet = (STCPHeader*)malloc(sizeof(STCPHeader));
  SYN_ACK_packet->th_seq = htonl(seq);
  SYN_ACK_packet->th_ack = htonl(ack);
  SYN_ACK_packet->th_off = htons(5);  // header size offset for packed data
  SYN_ACK_packet->th_flags = (TH_SYN | TH_ACK);  // set packet type to SYN_ACK
  SYN_ACK_packet->th_win = htons(WIND_SIZE);   // default value
  return SYN_ACK_packet;
}
bool send_ack_syn(mysocket_t sd, context_t *ctx)
{
    STCPHeader *stcp_header = create_syn_ack_packet(ctx->seq_num, ctx->recv_seq_num + 1);
    ctx->seq_num++;

    ssize_t sentBytes =
        stcp_network_send(sd, stcp_header, sizeof(STCPHeader), NULL);

    if (sentBytes > 0)
    {
        ctx->connection_state = SYN_ACK_SENT;
        free(stcp_header);
        stcp_header = NULL;
        return true;
    }
    else
    {
        free(stcp_header);
        free(ctx);
        stcp_header = NULL;
        ctx = NULL;
        errno = ECONNREFUSED; // TODO
        return false;
    }
}
void send_app_data(context_t *ctx, mysocket_t sd)
{
    unsigned int max_size = min(ctx->recv_wind_size,WIND_SIZE ) - sizeof(STCPHeader);
    printf("max_size: %d\n", max_size);
    printf("recv_wind_size: %d\n", ctx->recv_wind_size);
    char recv_buf[max_size];
    ssize_t recv_size = stcp_app_recv(sd, recv_buf, max_size);
    if (recv_size == 0)
    {
        free(ctx);
        ctx = NULL;
        errno = ECONNREFUSED;
        return ;
    }
    send_appdata_network(sd, ctx, recv_buf, recv_size);
    wait_for_event(sd, ctx, NETWORK_DATA, TH_ACK, CSTATE_ESTABLISHED);
}
STCPHeader *create_data_packet(unsigned int seq, unsigned int ack, char *buf, unsigned int recv_size)
{
    unsigned int DATA_packet_size = sizeof(STCPHeader) + recv_size;
    // printf("DATA Packet Payload Size: %d\n", DATA_packet_size);
    STCPHeader *DATA_packet = (STCPHeader *)malloc(DATA_packet_size);

    DATA_packet->th_seq = htonl(seq);
    DATA_packet->th_ack = htonl(ack);
    DATA_packet->th_flags = NETWORK_DATA;     //?
    DATA_packet->th_win = htons(WIND_SIZE); //?
    DATA_packet->th_off = htons(5);

    memcpy((char *)DATA_packet + sizeof(STCPHeader), buf, recv_size);
    return DATA_packet;
}
bool send_appdata_network(mysocket_t sd, context_t *ctx, char *recv_buf, unsigned int recv_size)
{
    //
    STCPHeader *packet = create_data_packet(ctx->seq_num, ctx->recv_seq_num + 1, recv_buf, recv_size);
    ctx->seq_num += recv_size;

    // Send DATA packet
    ssize_t sentBytes = stcp_network_send(
        sd, packet, sizeof(STCPHeader) + recv_size, NULL);
    // printf("Network Sent Bytes: %d\n", sentBytes);

    if (sentBytes > 0)
    { // If SYN_ACK packet suucessfully sent
        free(packet);
        return true;
    }
    else
    {
        free(packet);
        free(ctx);
        // stcp_unblock_application(sd);
        errno = ECONNREFUSED; // TODO
        return false;
    }
}
void parse_DATA_packet(context_t *ctx, char *buf, bool& isfin)
{
    STCPHeader *buf1 = (STCPHeader *)buf;
    ctx->recv_seq_num = ntohl(buf1->th_seq);
    ctx->recv_wind_size = ntohs(buf1->th_win);
    isfin = (buf1->th_flags == TH_FIN);
}
void parse_DATA_packet1(context_t* ctx, char* payload, bool& isFIN
                       ) {
  STCPHeader* payloadHeader = (STCPHeader*)payload;
  ctx->recv_seq_num = ntohl(payloadHeader->th_seq);
  ctx->recv_wind_size = ntohs(payloadHeader->th_win);
  isFIN = payloadHeader->th_flags == TH_FIN;
}
void send_DATA_packet_app(mysocket_t sd, context_t* ctx, char* payload,
                          size_t length) {
  // Send DATA packet
  stcp_app_send(sd, payload + sizeof(STCPHeader), length - sizeof(STCPHeader));
}
void recv_app_data(context_t *ctx,mysocket_t sd){
    bool isFIN = false;
  char payload[MAX_HEADER];

  ssize_t network_bytes = stcp_network_recv(sd, payload, MAX_HEADER);
  if (network_bytes < sizeof(STCPHeader)) {
    free(ctx);
    // stcp_unblock_application(sd);
    errno = ECONNREFUSED;  // TODO
    return;
  }

 // printSTCPHeader((STCPHeader*)payload);
  // printf("Network Data Payload: %s\n", payload + sizeof(STCPHeader));
  // printf("Network Bytes: %d\n", network_bytes);

  parse_DATA_packet1(ctx, payload, isFIN);


  if (isFIN) {
   // clock_gettime(CLOCK_REALTIME, &spec);
    // printf("%d isFIN\n", spec.tv_nsec);
    printf("get fin\n");
    send_ack(sd, ctx);
    stcp_fin_received(sd);
    ctx->connection_state = CSTATE_CLOSED;
    return;
  }

  if (network_bytes - sizeof(STCPHeader)) {
    printf("isDATA\n");
    send_DATA_packet_app(sd, ctx, payload, network_bytes);
    send_ack(sd, ctx);
  }
}


STCPHeader *create_fin_packet(unsigned int seq, unsigned int ack)
{
    STCPHeader *FIN_packet = (STCPHeader *)malloc(sizeof(STCPHeader));
    FIN_packet->th_seq = htonl(seq);
    FIN_packet->th_ack = htonl(ack);
    FIN_packet->th_flags = TH_FIN;
    FIN_packet->th_win = htons(WIND_SIZE);
    FIN_packet->th_off = htons(5);
    return FIN_packet;
}

bool send_fin(mysocket_t sd, context_t *ctx)
{
    STCPHeader *fin_packet =
        create_fin_packet(ctx->seq_num, ctx->recv_seq_num + 1);
    ctx->seq_num++;

    // Send FIN packet
    ssize_t sentBytes =
        stcp_network_send(sd, fin_packet, sizeof(STCPHeader), NULL);

    // Verify sending of FIN packet
    if (sentBytes > 0)
    { // If FIN packet suucessfully sent
        printf("send fin\n");
        ctx->connection_state = FIN_SEND;
        wait_for_event(sd, ctx, NETWORK_DATA, TH_ACK, CSTATE_ESTABLISHED);

        free(fin_packet);
        return true;
    }
    else
    {
        free(fin_packet);
        free(ctx);
        // stcp_unblock_application(sd);
        errno = ECONNREFUSED; // TODO
        return false;
    }
}
void app_close(context_t *ctx, mysocket_t sd)
{
   
    if (ctx->connection_state == CSTATE_ESTABLISHED)
    {
        printf("app close\n");
        send_fin(sd, ctx);
    }
}