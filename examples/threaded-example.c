/*
 * Copyright 2013 University of Chicago
 *  Contact: Bryce Allen
 * Copyright 2013 Collabora Ltd.
 *  Contact: Youness Alaoui
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * the GNU Lesser General Public License Version 2.1 (the "LGPL"), in which
 * case the provisions of LGPL are applicable instead of those above. If you
 * wish to allow use of your version of this file only under the terms of the
 * LGPL and not to allow others to use your version of this file under the
 * MPL, indicate your decision by deleting the provisions above and replace
 * them with the notice and other provisions required by the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under either the MPL or the LGPL.
 */

/*
 * Example using libnice to negotiate a UDP connection between two clients,
 * possibly on the same network or behind different NATs and/or stateful
 * firewalls.
 *
 * Build:
 *   gcc -o threaded-example threaded-example.c `pkg-config --cflags --libs nice`
 *
 * Run two clients, one controlling and one controlled:
 *   threaded-example 0 $(host -4 -t A stun.stunprotocol.org | awk '{ print $4 }')
 *   threaded-example 1 $(host -4 -t A stun.stunprotocol.org | awk '{ print $4 }')
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <agent.h>
#include <semaphore.h>
#include <gio/gnetworking.h>
#include <curl/curl.h>

#define IS_TEST 1
#define TEST_MAX_NUM 1e4
struct Signal_Struct
{ //用来存信令服务器发挥的response
    char *memory;
    size_t size;
};

gchar *signaling_addr = NULL;
guint signaling_port = 0;

static GMainLoop *gloop;
static gchar *stun_addr = NULL;
static guint stun_port;
static gboolean controlling;
static gboolean exit_thread, candidate_gathering_done, negotiation_done, ack_recvd;
static GMutex gather_mutex, negotiate_mutex, ack_mutex;
static GCond gather_cond, negotiate_cond;

static const gchar *candidate_type_name[] = {"host", "srflx", "prflx", "relay"};

static const gchar *state_name[] = {"disconnected", "gathering", "connecting",
                                    "connected", "ready", "failed"};

//static int print_local_data(NiceAgent *agent, guint stream_id,
//    guint component_id);
static int parse_remote_data(NiceAgent *agent, guint stream_id,
                             guint component_id, char *line);
static void cb_candidate_gathering_done(NiceAgent *agent, guint stream_id,
                                        gpointer data);
static void cb_new_selected_pair(NiceAgent *agent, guint stream_id,
                                 guint component_id, gchar *lfoundation,
                                 gchar *rfoundation, gpointer data);
static void cb_component_state_changed(NiceAgent *agent, guint stream_id,
                                       guint component_id, guint state,
                                       gpointer data);
static void cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id,
                         guint len, gchar *buf, gpointer data);
static void *example_thread(void *data);
static void *test_thread(NiceAgent *, guint);

//读response函数
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    char *ptr;
    struct Signal_Struct *mem = (struct Signal_Struct *)userp;

    /* iso */
    ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL)
    {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int main(int argc, char *argv[])
{
    GThread *gexamplethread;

    nice_debug_enable(1);

    if (argc > 6 || argc < 5 || argv[1][1] != '\0')
    {
        fprintf(stderr, "Usage: %s 0|1 stun_addr [stun_port] signaling_addr signaling port\n", argv[0]);
        return EXIT_FAILURE;
    }
    controlling = argv[1][0] - '0';
    if (controlling != 0 && controlling != 1)
    {
        fprintf(stderr, "Usage: %s 0|1 stun_addr [stun_port] signaling_addr signaling port\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc > 4)
    {
        stun_addr = argv[2];
        if (argc > 5)
        {
            stun_port = atoi(argv[3]);
            signaling_addr = argv[4];
            signaling_port = atoi(argv[5]);
        }
        else
        {
            stun_port = 3478;
            signaling_addr = argv[3];
            signaling_port = atoi(argv[4]);
        }

        g_debug("Using stun server '[%s]:%u' Using signaling server '[%s]:%u'\n", stun_addr, stun_port, signaling_addr, signaling_port);
    }

    gloop = g_main_loop_new(NULL, FALSE);

    // Run the mainloop and the example thread
    exit_thread = FALSE;
    gexamplethread = g_thread_new("example thread", &example_thread, NULL);
    g_main_loop_run(gloop);
    exit_thread = TRUE;

    g_thread_join(gexamplethread);
    g_main_loop_unref(gloop);

    return EXIT_SUCCESS;
}

static void *
example_thread(void *data)
{
    NiceAgent *agent;
    NiceCandidate *local, *remote;
    GIOChannel *io_stdin;
    guint stream_id;
    GIOStatus s;
    gchar *line = NULL;
    /* libcurl definitions */
    CURL *curl;
    GSList *item = NULL;
    NiceCandidate *c = NULL;
    CURLcode err;
    struct Signal_Struct peer_candidate;
    gchar post_data[1024] = {0};
    gchar candi[1024] = {0};
    gchar url[100];
    gchar *local_ufrag = NULL;
    gchar *local_password = NULL;
    GSList *cands = NULL;
    gchar ipaddr[INET6_ADDRSTRLEN];
    gchar *bf = NULL;
    gint len;
    CURLcode res;
    gint total_len = 0;
    int rval = 0;
    char *room = NULL;
    int error = 0;
    /* gio flag */
    GIOFlags flags;

#ifdef G_OS_WIN32
    io_stdin = g_io_channel_win32_new_fd(_fileno(stdin));
#else
    io_stdin = g_io_channel_unix_new(fileno(stdin));
#endif
    g_io_channel_set_flags(io_stdin, G_IO_FLAG_NONBLOCK, NULL);

    error = error;
    g_networking_init();
    flags = g_io_channel_get_flags(io_stdin);
    g_io_channel_set_flags(io_stdin, flags & ~G_IO_FLAG_NONBLOCK, NULL);
    // Create the nice agent
    agent = nice_agent_new(g_main_loop_get_context(gloop),
                                    NICE_COMPATIBILITY_RFC5245);
    if (agent == NULL)
        g_error("Failed to create agent");

    /* Set the STUN settings and controlling mode */
    if (stun_addr)
    {
        g_object_set(agent, "stun-server", stun_addr, NULL);
        g_object_set(agent, "stun-server-port", stun_port, NULL);
    }
    g_object_set(agent, "controlling-mode", controlling, NULL);

    /* Connect to the signals */
    g_signal_connect(agent, "candidate-gathering-done",
                     G_CALLBACK(cb_candidate_gathering_done), NULL);
    g_signal_connect(agent, "new-selected-pair",
                     G_CALLBACK(cb_new_selected_pair), NULL);
    g_signal_connect(agent, "component-state-changed",
                     G_CALLBACK(cb_component_state_changed), NULL);

    /* Create a new stream with one component */
    stream_id = nice_agent_add_stream(agent, 1);

    nice_agent_set_relay_info(agent, stream_id, 1, stun_addr, 3478, "username", "password", NICE_RELAY_TYPE_TURN_UDP);
    if (stream_id == 0)
        g_error("Failed to add stream");

    // Attach to the component to receive the data
    // Without this call, candidates cannot be gathered
    nice_agent_attach_recv(agent, stream_id, 1,
                           g_main_loop_get_context(gloop), cb_nice_recv, NULL);

    // Start gathering local candidates
    if (!nice_agent_gather_candidates(agent, stream_id))
        g_error("Failed to start candidate gathering");

    g_debug("waiting for candidate-gathering-done signal...");

    g_mutex_lock(&gather_mutex);
    while (!exit_thread && !candidate_gathering_done)
        g_cond_wait(&gather_cond, &gather_mutex);
    g_mutex_unlock(&gather_mutex);
    if (exit_thread)
        goto end;

    //与信令服务器交互，完成candidate交换
    puts("begin to communicate with signaling");
    peer_candidate.memory = malloc(1);
    peer_candidate.size = 0;
    //int len;
    curl = curl_easy_init();
    sprintf(url, "http://%s:%d", signaling_addr, signaling_port);
    if (curl)
    {
        //链接到服务器
        err = curl_easy_setopt(curl, CURLOPT_URL, url);
        //错误检查
        if (err != CURLE_OK)
        {
            g_error("something wrong when set url");
        }
        //等待输入房间号
        while (1)
        {
            printf("Enter the room number(四位数字):\n");
            printf("> ");
            //fflush(stdout);
            s = g_io_channel_read_line(io_stdin, &line, NULL, NULL, NULL);
            if (s == G_IO_STATUS_NORMAL)
            {
                g_info("fuck 0");
                room = line;
                g_info("the room you want: %s", room);
                //g_free(line);
                break;
            }
            else if (s == G_IO_STATUS_AGAIN)
            {
                g_usleep(100000);
            }
        }
        //获取账号密码 p.s.容易忘记释放
        if (!nice_agent_get_local_credentials(agent, stream_id, &local_ufrag, &local_password))
            g_error("something wrong when get the credentials");

        //获取candidates
        cands = nice_agent_get_local_candidates(agent, stream_id, (gint)1);

        if (cands == NULL)
            g_error("something wrong when get the candidate");
        //开始封装candidate到post_data中
        bf = candi;
        //先是用户名密码

        len = sprintf(candi, "%s %s", local_ufrag, local_password);
        total_len = len;
        //然后candidate
        for (item = cands; item; item = item->next)
        {
            c = (NiceCandidate *)item->data;
            nice_address_to_string(&c->addr, ipaddr);
            bf = bf + len;
            // (foundation),(prio),(addr),(port),(type)
            len = sprintf(bf, " %s,%u,%s,%u,%s",
                          c->foundation,
                          c->priority,
                          ipaddr,
                          nice_address_get_port(&c->addr),
                          candidate_type_name[c->type]);
            total_len = total_len + len;
        }
        //把room最后换成\0
        room[4] = '\0';
        sprintf(post_data,
                "{\"room\":\"%s\", \"name\":\"%s\", \"candidate\":\"%s\"}",
                room, local_ufrag, candi);
        //打包完毕，清理一下
        if (local_ufrag)
            free(local_ufrag);

        if (local_password)
            free(local_password);

        //打印一下自身candidate
        printf("cadidate info: %s\n", post_data);
        err = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        if (err != CURLE_OK)
        {
            g_error("there is something wrong when set the postdata");
        }
        //准 备 接 收 candidate
        err = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        err = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&peer_candidate);
        printf("transfering cadidate info...\n");
        while (1)
        {
            res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                fprintf(stderr, "curl_easy_perform() fialed: res = %d %s\n", res, curl_easy_strerror(res));
                //再来一遍或者处理其他问题
                switch (res)
                {
                case 7:
                jump_retry:
                    printf("sorry, please try another one or try again, enter the signaling address\n");
                    printf(">\n");
                    error = scanf("%s", signaling_addr);
                    printf("and the port\n");
                    printf(">\n");
                    error = scanf("%d", &signaling_port);
                    //重设url
                    sprintf(url, "http://%s:%d", signaling_addr, signaling_port);
                    curl_easy_setopt(curl, CURLOPT_URL, url);
                    break;
                case 6:
                    printf("sorry, you enter a wrong ip addr, enter the signaling address\n");
                    printf(">\n");
                    error = scanf("%s", signaling_addr);
                    printf("and the port\n");
                    printf(">\n");
                    error = scanf("%d", &signaling_port);
                    //重设url
                    sprintf(url, "http://%s:%d", signaling_addr, signaling_port);
                    curl_easy_setopt(curl, CURLOPT_URL, url);
                    break;

                default:
                    printf("sorry, we meet a fault that we cannot fixed, please close\n");
                    //跳到结束处
                    curl_easy_cleanup(curl);
                    goto end;
                    break;
                }
            }
            else
                break;
        }

        printf("we recieved the signal message: %s\n", peer_candidate.memory);
        if (strncmp(peer_candidate.memory, "fail", 4) == 0)
        {
            //有可能是失败哦 加处理
            printf("fail to join/create a room\n");
            goto jump_retry;
        }
        else if (strncmp(peer_candidate.memory, "timeout", 7) == 0)
        {
            printf("time limit exceed\n");
            goto jump_retry;
        }

        printf("parsing remote cadidate...!\n");
        rval = parse_remote_data(agent, stream_id, 1, peer_candidate.memory);
        if (rval != EXIT_SUCCESS)
        { //解析失败
            g_error("something wrong when parse the candidate");
            //重试
        }
    }
    else
    {
        g_error("failed to create curl");
    }
    curl_easy_cleanup(curl);
    printf("done\n");

    g_debug("waiting for state READY or FAILED signal...");
    g_mutex_lock(&negotiate_mutex);
    while (!exit_thread && !negotiation_done)
        g_cond_wait(&negotiate_cond, &negotiate_mutex);
    g_mutex_unlock(&negotiate_mutex);
    if (exit_thread)
        goto end;

    // Get current selected candidate pair and print IP address used
    if (nice_agent_get_selected_pair(agent, stream_id, 1,
                                     &local, &remote))
    {
        nice_address_to_string(&local->addr, ipaddr);
        printf("\nNegotiation complete: ([%s]:%d,",
               ipaddr, nice_address_get_port(&local->addr));
        nice_address_to_string(&remote->addr, ipaddr);
        printf(" [%s]:%d)\n", ipaddr, nice_address_get_port(&remote->addr));
    }

    if (IS_TEST && controlling) {
        // if ((test_fd = dup(fileno(stdin))) < 0) {
        //     perror("dup");
        //     return NULL;
        // }
        //fclose(stdin);
        test_thread(agent, stream_id);
    } else {
        /* Listen to stdin and send data written to it */
        printf("\nSend lines to remote (Ctrl-D to quit):\n");
        printf("> ");
        fflush(stdout);
        while (!exit_thread)
        {
            /*GIOStatus*/ s = g_io_channel_read_line(io_stdin, &line, NULL, NULL, NULL);
            if (s == G_IO_STATUS_NORMAL)
            {
                nice_agent_send(agent, stream_id, 1, strlen(line), line);
                g_free(line);
                printf("> ");
                fflush(stdout);
            }
            else if (s == G_IO_STATUS_AGAIN)
            {
                g_usleep(100000);
            }
            else
            {
                /* Ctrl-D was pressed. */
                nice_agent_send(agent, stream_id, 1, 1, "\0");
                break;
            }
        }
    }

end:
    g_io_channel_unref(io_stdin);
    g_object_unref(agent);
    g_main_loop_quit(gloop);
    return NULL;
}

static void *
test_thread(NiceAgent *agent, guint stream_id)
{
    char buff[1024] = {0};
    int num = 0;
    ack_recvd = FALSE;
    //int test_fd = (int)(long)data;
    // write to test_fd[1] so that main thread can see
    while (1) { /* forever */
        bzero(buff, sizeof(buff));
        sprintf(buff, "%d\n", ++num);
        /* get statistic info here */
        if (num >= TEST_MAX_NUM) {
            num = 0;
        }
        if (nice_agent_send(agent, stream_id, 1, strlen(buff), buff) < 0) {
            perror("test send");
            exit(-1);
        }
        if (num == 0) {
            g_mutex_lock(&ack_mutex);
            while (!ack_recvd) {
                g_mutex_unlock(&ack_mutex);
                if(nice_agent_send(agent, stream_id, 1, strlen("end"), "end") <= 0) {
                    perror("test end");
                    exit(-1);
                }
                usleep(10000);
                g_mutex_lock(&ack_mutex);
            }
            g_mutex_unlock(&ack_mutex);
        }
        ack_recvd = FALSE;
    }
    //close(test_fd);
    return NULL;
}

static void
cb_candidate_gathering_done(NiceAgent *agent, guint stream_id,
                            gpointer data)
{
    g_debug("SIGNAL candidate gathering done\n");

    g_mutex_lock(&gather_mutex);
    candidate_gathering_done = TRUE;
    g_cond_signal(&gather_cond);
    g_mutex_unlock(&gather_mutex);
}

static void
cb_component_state_changed(NiceAgent *agent, guint stream_id,
                           guint component_id, guint state,
                           gpointer data)
{
    g_debug("SIGNAL: state changed %d %d %s[%d]\n",
            stream_id, component_id, state_name[state], state);

    if (state == NICE_COMPONENT_STATE_READY)
    {
        g_mutex_lock(&negotiate_mutex);
        negotiation_done = TRUE;
        g_cond_signal(&negotiate_cond);
        g_mutex_unlock(&negotiate_mutex);
    }
    else if (state == NICE_COMPONENT_STATE_FAILED)
    {
        g_main_loop_quit(gloop);
    }
}

static void
cb_new_selected_pair(NiceAgent *agent, guint stream_id,
                     guint component_id, gchar *lfoundation,
                     gchar *rfoundation, gpointer data)
{
    g_debug("SIGNAL: selected pair %s %s", lfoundation, rfoundation);
}

static void
cb_nice_recv(NiceAgent *agent, guint stream_id, guint component_id,
             guint len, gchar *buf, gpointer data)
{
    static int recv_count = 0;
    char *nxt;

    if (len == 1 && buf[0] == '\0') {
        printf("%d, %s", len, buf);
        g_main_loop_quit(gloop);
    }

    buf[len] = '\0';
    if (IS_TEST && !controlling) {
        if (len >= 3 && strncmp("end", buf, 3) == 0) {
            if (nice_agent_send(agent, stream_id, 1, strlen("ack"), "ack") < 0) {
                ;/* give up */
            }
            if (recv_count != 0)
                printf("pakcket loss: %f\n", 1 - 1.0 * recv_count / TEST_MAX_NUM);
            recv_count = 0;
            return;
        }
        while (buf != NULL && *buf != '\0') {
            /* get a line */
            nxt = buf;
            while (*nxt != '\n' && *nxt) {
                nxt++;
            }
            recv_count++;

            buf = *nxt == 0 ? 0 : nxt + 1;
        }
    } else if (IS_TEST && controlling) {
        if (len <= 1)
            return;
        if (strncmp(buf, "ack", 3) == 0) {
            g_mutex_lock(&gather_mutex);
            ack_recvd = TRUE;
            g_mutex_unlock(&gather_mutex);
        }
    } else {
        printf("%s", buf);
        fflush(stdout);
    }
}

static NiceCandidate *
parse_candidate(char *scand, guint stream_id)
{
    NiceCandidate *cand = NULL;
    NiceCandidateType ntype = NICE_CANDIDATE_TYPE_HOST;
    gchar **tokens = NULL;
    guint i;

    tokens = g_strsplit(scand, ",", 5);
    for (i = 0; tokens[i]; i++)
        ;
    if (i != 5)
        goto end;

    for (i = 0; i < G_N_ELEMENTS(candidate_type_name); i++)
    {
        if (strcmp(tokens[4], candidate_type_name[i]) == 0)
        {
            ntype = i;
            break;
        }
    }
    if (i == G_N_ELEMENTS(candidate_type_name))
        goto end;

    cand = nice_candidate_new(ntype);
    cand->component_id = 1;
    cand->stream_id = stream_id;
    cand->transport = NICE_CANDIDATE_TRANSPORT_UDP;
    strncpy(cand->foundation, tokens[0], NICE_CANDIDATE_MAX_FOUNDATION - 1);
    cand->foundation[NICE_CANDIDATE_MAX_FOUNDATION - 1] = 0;
    cand->priority = atoi(tokens[1]);

    if (!nice_address_set_from_string(&cand->addr, tokens[2]))
    {
        g_message("failed to parse addr: %s", tokens[2]);
        nice_candidate_free(cand);
        cand = NULL;
        goto end;
    }

    nice_address_set_port(&cand->addr, atoi(tokens[3]));

end:
    g_strfreev(tokens);

    return cand;
}

static int
parse_remote_data(NiceAgent *agent, guint stream_id,
                  guint component_id, char *line)
{
    GSList *remote_candidates = NULL;
    gchar **line_argv = NULL;
    const gchar *ufrag = NULL;
    const gchar *passwd = NULL;
    int result = EXIT_FAILURE;
    int i;

    line_argv = g_strsplit_set(line, " \t\n", 0);
    for (i = 0; line_argv && line_argv[i]; i++)
    {
        if (strlen(line_argv[i]) == 0)
            continue;

        // first two args are remote ufrag and password
        if (!ufrag)
        {
            ufrag = line_argv[i];
        }
        else if (!passwd)
        {
            passwd = line_argv[i];
        }
        else
        {
            // Remaining args are serialized canidates (at least one is required)
            NiceCandidate *c = parse_candidate(line_argv[i], stream_id);

            if (c == NULL)
            {
                g_message("failed to parse candidate: %s", line_argv[i]);
                goto end;
            }
            remote_candidates = g_slist_prepend(remote_candidates, c);
        }
    }
    if (ufrag == NULL || passwd == NULL || remote_candidates == NULL)
    {
        g_message("line must have at least ufrag, password, and one candidate");
        goto end;
    }

    if (!nice_agent_set_remote_credentials(agent, stream_id, ufrag, passwd))
    {
        g_message("failed to set remote credentials");
        goto end;
    }

    // Note: this will trigger the start of negotiation.
    if (nice_agent_set_remote_candidates(agent, stream_id, component_id,
                                         remote_candidates) < 1)
    {
        g_message("failed to set remote candidates");
        goto end;
    }

    result = EXIT_SUCCESS;

end:
    if (line_argv != NULL)
        g_strfreev(line_argv);
    if (remote_candidates != NULL)
        g_slist_free_full(remote_candidates, (GDestroyNotify)&nice_candidate_free);

    return result;
}