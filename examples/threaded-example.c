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
#include <gio/gnetworking.h>
#include<curl/curl.h>

//******user_add
char *strrpl(char* s, const char* s1, const char* s2);
char *strrpl(char *s, const char *s1, const char *s2)
{
char *ptr;
ptr = strstr(s,s1);
while (ptr) /* 如果在s中找到s1 */
{
memmove(ptr + strlen(s2) , ptr + strlen(s1), strlen(ptr) - strlen(s1) + 1);
memcpy(ptr, s2, strlen(s2));
ptr = strstr(s,s1);
}
return s;
}

//
struct Signal_Struct { //用来存信令服务器发挥的response
	char * memory;
	size_t size;
};
//读response函数
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  char *ptr;
  struct Signal_Struct *mem = (struct Signal_Struct *)userp;
	printf("123");
  //iso
  ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) {
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

gchar *signaling_addr = NULL;
guint signaling_port = 0;

static GMainLoop *gloop;
static gchar *stun_addr = NULL;
static guint stun_port;
static gboolean controlling;
static gboolean exit_thread, candidate_gathering_done, negotiation_done;
static GMutex gather_mutex, negotiate_mutex;
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
//g_networking_init();
static void * example_thread(void *data);

//*************user_add*************
/*static int
communicate_signaling(NiceAgent *agent, guint _stream_id,guint component_id);
static int
communicate_signaling_passive(NiceAgent *agent, guint _stream_id,guint component_id);
*/
//**********************************

int
main(int argc, char *argv[])
{
  GThread *gexamplethread;

  nice_debug_enable(1);
//******user_add

    if (argc > 6 || argc < 5 || argv[1][1] != '\0') {
        fprintf(stderr, "Usage: %s 0|1 stun_addr [stun_port] signaling_addr signaling port\n", argv[0]);
        return EXIT_FAILURE;
    }
    controlling = argv[1][0] - '0';
    if (controlling != 0 && controlling != 1) {
        fprintf(stderr, "Usage: %s 0|1 stun_addr [stun_port] signaling_addr signaling port\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc > 4) {
        stun_addr = argv[2];
        if (argc > 5) {
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


    //**************
  // Parse arguments
//  if (argc > 4 || argc < 2 || argv[1][1] != '\0') {
//    fprintf(stderr, "Usage: %s 0|1 stun_addr [stun_port]\n", argv[0]);
//    return EXIT_FAILURE;
//  }
//  controlling = argv[1][0] - '0';
//  if (controlling != 0 && controlling != 1) {
//    fprintf(stderr, "Usage: %s 0|1 stun_addr [stun_port]\n", argv[0]);
//    return EXIT_FAILURE;
//  }
//
//  if (argc > 2) {
//    stun_addr = argv[2];
//    if (argc > 3)
//      stun_port = atoi(argv[3]);
//    else
//      stun_port = 3478;
//
//    g_debug("Using stun server '[%s]:%u'\n", stun_addr, stun_port);
//  }


  gloop = g_main_loop_new(NULL, FALSE);

  // Run the mainloop and the example thread
  exit_thread = FALSE;
  gexamplethread = g_thread_new("example thread", &example_thread, NULL);
  g_main_loop_run (gloop);
  exit_thread = TRUE;

  g_thread_join (gexamplethread);
  g_main_loop_unref(gloop);

  return EXIT_SUCCESS;
}

static void *
example_thread(void *data)
{
  NiceAgent *agent;
  NiceCandidate *local, *remote;
  GIOChannel* io_stdin;
  guint stream_id;
  GIOStatus s;
  gchar *line = NULL;

  //user_add*******
  CURL *curl;
  GSList *item = NULL;
  NiceCandidate *c = NULL;
  CURLcode err; 
  struct Signal_Struct peer_candidate;
  gchar post_data[1024] = {0};
  gchar candi[1024] = {0};
  gchar url[100];  
  gchar *local_ufrag = NULL ;
  gchar *local_password = NULL;
  GSList *cands = NULL;
  gchar ipaddr[INET6_ADDRSTRLEN];
  gchar *bf = NULL;
  gint len;
  CURLcode res; 
  gint total_len = 0;
  int rval = 0;
  char* room = NULL;
  int error = 0;
//user_add*******
  GIOFlags flags;	  
  //int rval;

#ifdef G_OS_WIN32
  io_stdin = g_io_channel_win32_new_fd(_fileno(stdin));
#else
  io_stdin = g_io_channel_unix_new(fileno(stdin));
#endif
  g_io_channel_set_flags (io_stdin, G_IO_FLAG_NONBLOCK, NULL);

  error = error;
  g_networking_init();
  flags = g_io_channel_get_flags(io_stdin);
  g_io_channel_set_flags(io_stdin, flags&~G_IO_FLAG_NONBLOCK,NULL);
  // Create the nice agent
  agent = nice_agent_new_reliable(g_main_loop_get_context (gloop),
      NICE_COMPATIBILITY_RFC5245);
  if (agent == NULL)
    g_error("Failed to create agent");

  // Set the STUN settings and controlling mode
  if (stun_addr) {
    g_object_set(agent, "stun-server", stun_addr, NULL);
    g_object_set(agent, "stun-server-port", stun_port, NULL);
  }
  g_object_set(agent, "controlling-mode", controlling, NULL);

  // Connect to the signals
  g_signal_connect(agent, "candidate-gathering-done",
      G_CALLBACK(cb_candidate_gathering_done), NULL);
  g_signal_connect(agent, "new-selected-pair",
      G_CALLBACK(cb_new_selected_pair), NULL);
  g_signal_connect(agent, "component-state-changed",
      G_CALLBACK(cb_component_state_changed), NULL);

  // Create a new stream with one component
  stream_id = nice_agent_add_stream(agent,1);

  nice_agent_set_relay_info(agent,stream_id,1,stun_addr,3478,"username","password",NICE_RELAY_TYPE_TURN_UDP);
  if (stream_id == 0)
    g_error("Failed to add stream");

  // Attach to the component to receive the data
  // Without this call, candidates cannot be gathered
  nice_agent_attach_recv(agent, stream_id, 1,
      g_main_loop_get_context (gloop), cb_nice_recv, NULL);

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

  // Candidate gathering is done. Send our local candidates on stdout
//  printf("Copy this line to remote client:\n");
//  printf("\n  ");
//  print_local_data(agent, stream_id, 1);
//  printf("\n");
 
//*********user_add
  //等待输入房间号
//        while(1){
//        printf("Enter the room number(四位数字):\n");
//        printf("> ");
//        fflush(stdout);
//        s = g_io_channel_read_line(io_stdin, &line, NULL, NULL, NULL);
//        if (s == G_IO_STATUS_NORMAL) {
//                g_info("fuck 0");
//                room = line;
//                g_info("the room you want: %s",room);
//                g_free(line);
//             break;
//          } else if(s == G_IO_STATUS_AGAIN){
//              g_usleep (100000);
//          }
//        }
//

  //与信令服务器交互，完成candidate交换
  puts("begin to communicate with signaling");
  peer_candidate.memory = malloc(1);
  peer_candidate.size = 0;
  puts("1fuck");
  //int len;
  curl = curl_easy_init();
  puts("2fuck");
  sprintf(url,"http://%s:%d",signaling_addr,signaling_port);
  puts("3fuck");
  if(curl){
	//链接到服务器
	err = curl_easy_setopt(curl ,CURLOPT_URL,url);
	//错误检查
	if(err != CURLE_OK){
		g_error("something wrong when set url");
	}	
	//等待输入房间号
	while(1){
	printf("Enter the room number(四位数字):\n");
        printf("> ");
        //fflush(stdout);
       	s = g_io_channel_read_line(io_stdin, &line, NULL, NULL, NULL);
	if (s == G_IO_STATUS_NORMAL) {
		g_info("fuck 0");
		room = line;
		g_info("the room you want: %s",room);
	        //g_free(line);
             break;
          } else if(s == G_IO_STATUS_AGAIN){
              g_usleep (100000);
          }
	}
	//获取账号密码 p.s.容易忘记释放
    	if (!nice_agent_get_local_credentials(agent, stream_id,&local_ufrag, &local_password))
        	g_error("something wrong when get the credentials");
 	puts("fuck1");  
       	//获取candidates	
	cands = nice_agent_get_local_candidates(agent, stream_id,(gint) 1);
	puts("fuck3");
	if (cands == NULL)
		 g_error("something wrong when get the candidate");
	//开始封装candidate到post_data中
	bf = candi;
    	//先是用户名密码
	puts("fuck2");
	len= sprintf(candi,"%s %s", local_ufrag, local_password);
	total_len = len;
    	puts("fuck4");
	//然后candidate
	for ( item = cands; item; item = item->next) {
		c = (NiceCandidate *)item->data;
       		nice_address_to_string(&c->addr, ipaddr);
        	bf = bf + len;
        	// (foundation),(prio),(addr),(port),(type)
        	len = sprintf(bf," %s,%u,%s,%u,%s",
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
            room,local_ufrag,candi);
	//打包完毕，清理一下
	if(local_ufrag)
		free(local_ufrag);
	puts("fuck5");
	if(local_password)
		free(local_password);
	puts("fuck6");
	//打印一下自身candidate
	printf("%s\n",post_data);
	//清理 over
	//因为post中不能含有+ % /字符 所以处理一下
	//strrpl(post_data,"+",".0x2B");
	//strrpl(post_data,"%",".0x25");
	//strrpl(post_data,"/",".0x2F");
	//在打印看一下
	//printf("转换后：%s\n",post_data);
	err = curl_easy_setopt(curl,CURLOPT_POSTFIELDS, post_data);
	if(err != CURLE_OK){
		g_error("there is something wrong when set the postdata");
	}
	//准 备 接 收 candidate
	err = curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,WriteMemoryCallback);
	err = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&peer_candidate);
	printf("***********let's do it!!!************\n");
	while(1){
		res = curl_easy_perform(curl);
		if(res != CURLE_OK){
			fprintf(stderr, "curl_easy_perform() fialed: res = %d %s\n",res,curl_easy_strerror(res));
			//再来一遍或者处理其他问题
			switch(res){
				case 7:
jump_retry:
					printf("sorry, please try another one or try again, enter the signaling address\n");
					printf(">\n");
					error = scanf("%s", signaling_addr);
					printf("and the port\n");
					printf(">\n");
					error = scanf("%d", &signaling_port);
  					//重设url
					sprintf(url,"http://%s:%d",signaling_addr,signaling_port);
					curl_easy_setopt(curl,CURLOPT_URL,url);
					break;
				case 6: 
					printf("sorry, you enter a wrong ip addr, enter the signaling address\n");
					printf(">\n");
					error = scanf("%s", signaling_addr);
					printf("and the port\n");
					printf(">\n");
					error = scanf("%d", &signaling_port);
  					//重设url
					sprintf(url,"http://%s:%d",signaling_addr,signaling_port);
					curl_easy_setopt(curl,CURLOPT_URL,url);
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
	if(strncmp(peer_candidate.memory,"fail",4) == 0 )
	{
	//有可能是失败哦 加处理
		printf("fail to join/create a room ");
		goto jump_retry;
	}
	else if(strncmp(peer_candidate.memory,"timeout",7) == 0 )
	{
		printf("waiting for too long ");
		goto jump_retry;
	}
	//字符转换处理
	//strrpl(peer_candidate.memory,".0x2B","+");
        //strrpl(peer_candidate.memory,".0x25","%");
        //strrpl(peer_candidate.memory,".0x2F","/");	
	printf("parse remote data begin! !\n");
		 rval = parse_remote_data(agent,stream_id, 1,peer_candidate.memory);
		if(rval != EXIT_SUCCESS){ //解析失败
		g_error("something wrong when parse the candidate");
		
		//重试
		}
  }
  else{
	g_error("failed to create curl");
  }
	curl_easy_cleanup(curl);	
	printf("***********done*******\n");
 
// Listen on stdin for the remote candidate list
//  printf("Enter remote data (single line, no wrapping):\n");
//  printf("> ");
//  GIOStatus s;
//  fflush (stdout);
//  while (!exit_thread) {
//    s = g_io_channel_read_line (io_stdin, &line, NULL, NULL, NULL);
//    if (s == G_IO_STATUS_NORMAL) {
//      // Parse remote candidate list and set it on the agent
//      rval = parse_remote_data(agent, stream_id, 1, line);
//      if (rval == EXIT_SUCCESS) {
//        g_free (line);
//        break;
//      } else {
//        fprintf(stderr, "ERROR: failed to parse remote data\n");
//        printf("Enter remote data (single line, no wrapping):\n");
//        printf("> ");
//        fflush (stdout);
//      }
//      g_free (line);
//    } else if (s == G_IO_STATUS_AGAIN) {
//      g_usleep (100000);
//    }
//  }

  g_debug("waiting for state READY or FAILED signal...");
  g_mutex_lock(&negotiate_mutex);
  while (!exit_thread && !negotiation_done)
    g_cond_wait(&negotiate_cond, &negotiate_mutex);
  g_mutex_unlock(&negotiate_mutex);
  if (exit_thread)
    goto end;

  // Get current selected candidate pair and print IP address used
  if (nice_agent_get_selected_pair (agent, stream_id, 1,
          &local, &remote)) {

    nice_address_to_string(&local->addr, ipaddr);
    printf("\nNegotiation complete: ([%s]:%d,",
        ipaddr, nice_address_get_port(&local->addr));
    nice_address_to_string(&remote->addr, ipaddr);
    printf(" [%s]:%d)\n", ipaddr, nice_address_get_port(&remote->addr));
  }

  // Listen to stdin and send data written to it
  printf("\nSend lines to remote (Ctrl-D to quit):\n");
  printf("> ");
  fflush (stdout);
  while (!exit_thread) {
    /*GIOStatus*/ s = g_io_channel_read_line (io_stdin, &line, NULL, NULL, NULL);
    if (s == G_IO_STATUS_NORMAL) {
      nice_agent_send(agent, stream_id, 1, strlen(line), line);
      g_free (line);
      printf("> ");
      fflush (stdout);
    } else if (s == G_IO_STATUS_AGAIN) {
      g_usleep (100000);
    } else {
      // Ctrl-D was pressed.
      nice_agent_send(agent, stream_id, 1, 1, "\0");
      break;
    }
  }

end:
  g_io_channel_unref (io_stdin);
  g_object_unref(agent);
  g_main_loop_quit (gloop);

  //if(room)
	  //free(room);

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

  if (state == NICE_COMPONENT_STATE_READY) {
    g_mutex_lock(&negotiate_mutex);
    negotiation_done = TRUE;
    g_cond_signal(&negotiate_cond);
    g_mutex_unlock(&negotiate_mutex);
  } else if (state == NICE_COMPONENT_STATE_FAILED) {
    g_main_loop_quit (gloop);
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
  if (len == 1 && buf[0] == '\0')
    g_main_loop_quit (gloop);

  //count++;
  printf("%.*s", len, buf);
 // printf("i am in cb_nice_recv\n");
  //printf("count : %ld\n" , count);
  fflush(stdout);
}

static NiceCandidate *
parse_candidate(char *scand, guint stream_id)
{
  NiceCandidate *cand = NULL;
  NiceCandidateType ntype = NICE_CANDIDATE_TYPE_HOST;
  gchar **tokens = NULL;
  guint i;

  printf("begin parse candidate\n");
  tokens = g_strsplit (scand, ",", 5);
  for (i = 0; tokens[i]; i++);
  if (i != 5)
    goto end;

  for (i = 0; i < G_N_ELEMENTS (candidate_type_name); i++) {
    if (strcmp(tokens[4], candidate_type_name[i]) == 0) {
      ntype = i;
      break;
    }
  }
  if (i == G_N_ELEMENTS (candidate_type_name))
    goto end;

  cand = nice_candidate_new(ntype);
  cand->component_id = 1;
  cand->stream_id = stream_id;
  cand->transport = NICE_CANDIDATE_TRANSPORT_UDP;
  strncpy(cand->foundation, tokens[0], NICE_CANDIDATE_MAX_FOUNDATION - 1);
  cand->foundation[NICE_CANDIDATE_MAX_FOUNDATION - 1] = 0;
  cand->priority = atoi (tokens[1]);

  if (!nice_address_set_from_string(&cand->addr, tokens[2])) {
    g_message("failed to parse addr: %s", tokens[2]);
    nice_candidate_free(cand);
    cand = NULL;
    goto end;
  }

  nice_address_set_port(&cand->addr, atoi (tokens[3]));

 end:
  g_strfreev(tokens);

  return cand;
}


//static int
//print_local_data (NiceAgent *agent, guint stream_id, guint component_id)
//{
//  int result = EXIT_FAILURE;
//  gchar *local_ufrag = NULL;
//  gchar *local_password = NULL;
//  gchar ipaddr[INET6_ADDRSTRLEN];
//  GSList *cands = NULL, *item;
//
//  if (!nice_agent_get_local_credentials(agent, stream_id,
//      &local_ufrag, &local_password))
//    goto end;
//
//  cands = nice_agent_get_local_candidates(agent, stream_id, component_id);
//  if (cands == NULL)
//    goto end;
//
//  printf("%s %s", local_ufrag, local_password);
//
//  for (item = cands; item; item = item->next) {
//    NiceCandidate *c = (NiceCandidate *)item->data;
//
//    nice_address_to_string(&c->addr, ipaddr);
//
//    // (foundation),(prio),(addr),(port),(type)
//    printf(" %s,%u,%s,%u,%s",
//        c->foundation,
//        c->priority,
//        ipaddr,
//        nice_address_get_port(&c->addr),
//        candidate_type_name[c->type]);
//  }
//  printf("\n");
//  result = EXIT_SUCCESS;
//
// end:
//  if (local_ufrag)
//    g_free(local_ufrag);
//  if (local_password)
//    g_free(local_password);
//  if (cands)
//    g_slist_free_full(cands, (GDestroyNotify)&nice_candidate_free);
//
//  return result;
//}


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

  line_argv = g_strsplit_set (line, " \t\n", 0);
  for (i = 0; line_argv && line_argv[i]; i++) {
    if (strlen (line_argv[i]) == 0)
      continue;

    // first two args are remote ufrag and password
    if (!ufrag) {
      ufrag = line_argv[i];
    } else if (!passwd) {
      passwd = line_argv[i];
    } else {
      // Remaining args are serialized canidates (at least one is required)
      NiceCandidate *c = parse_candidate(line_argv[i], stream_id);

      if (c == NULL) {
        g_message("failed to parse candidate: %s", line_argv[i]);
        goto end;
      }
      remote_candidates = g_slist_prepend(remote_candidates, c);
    }
  }
  if (ufrag == NULL || passwd == NULL || remote_candidates == NULL) {
    g_message("line must have at least ufrag, password, and one candidate");
    goto end;
  }

  if (!nice_agent_set_remote_credentials(agent, stream_id, ufrag, passwd)) {
    g_message("failed to set remote credentials");
    goto end;
  }

  // Note: this will trigger the start of negotiation.
  if (nice_agent_set_remote_candidates(agent, stream_id, component_id,
      remote_candidates) < 1) {
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
//**********user_add
/*static int
communicate_signaling_passive(NiceAgent *agent, guint _stream_id,guint component_id)
{
    gchar *local_ufrag = NULL;  //本地用户名
    gchar *local_password = NULL;   //本地密码
    gchar ipaddr[INET6_ADDRSTRLEN]; //
    GSList *cands = NULL, *item;    //
    GSocketClient * client = NULL;
    GError *error = NULL;
    GOutputStream * out_stream = NULL;
    gssize ret_int = 0;
    char *buffer_recv = NULL;
    char buffer_send[1024] = {0};
    gsize len =0;
    GSocketConnection *connection = NULL;
    GSocket *socket = NULL;
    GIOChannel *channel = NULL;
    gint fd = 0;
    GIOStatus ret;
    char *bf;
    gsize total_len;	
    int rval;
    GIOFlags flags;



    //获取账号密码
    if (!nice_agent_get_local_credentials(agent, _stream_id,
                                          &local_ufrag, &local_password))
        goto end;
    //获取candidates
    cands = nice_agent_get_local_candidates(agent, _stream_id, component_id);
    if (cands == NULL)
        goto end;
    //建立tcp连接
    client = g_socket_client_new();
    connection = g_socket_client_connect_to_host (client,signaling_addr,signaling_port,NULL,&error);
    if (error){
        printf("fail to connect with the signaling server, please try manual method");
	    g_error("Error: %s\n", error->message);
	    exit(1);
    }else{
        g_message("Connected with signaling ！");
    }
    out_stream = g_io_stream_get_output_stream(G_IO_STREAM(connection));

    socket = g_socket_connection_get_socket(connection);
    fd = g_socket_get_fd(socket);
    channel = g_io_channel_unix_new(fd);
    flags = g_io_channel_get_flags (channel);
    g_io_channel_set_flags (channel, flags & ~G_IO_FLAG_NONBLOCK, NULL);
    if(!channel)
    {
        goto end;
    }
    //发送join请求

    bf = buffer_send;
    len = sprintf(bf,"JOIN\n%s",room);
    total_len = len;
    //发送自身的candidate到服务器房间
    //先是用户名密码
    bf = bf + len;
    len = sprintf(bf,"%s %s", local_ufrag, local_password);
    total_len += len;
    for (item = cands; item; item = item->next) {
        NiceCandidate *c = (NiceCandidate *)item->data;
        nice_address_to_string(&c->addr, ipaddr);
        bf = bf + len;
        len = sprintf(bf," %s,%u,%s,%u,%s",
                      c->foundation,
                      c->priority,
                      ipaddr,
                      nice_address_get_port(&c->addr),
                      candidate_type_name[c->type]);
        total_len = total_len + len;
        // (foundation),(prio),(addr),(port),(type)
    }
    len = sprintf(bf+len,"\n");
    total_len = total_len + len;
    printf("send is :%s", buffer_send);

    ret_int = g_output_stream_write(out_stream, buffer_send,total_len , NULL, NULL);
    g_output_stream_flush(out_stream, NULL, NULL);

    if((unsigned int)ret_int == total_len)
    {
        g_message("writen the request message and candidate");
    }else if(ret_int < 1)
    {
        g_error("write error");
    }
    else
        g_error("write less than request");

    //等待对方的candidate
    printf("waiting for the remote candidate.....\n");
    if(buffer_recv) {
	   g_free(buffer_recv);
	   buffer_recv = NULL;
    }
    while(1)
    {
        ret = g_io_channel_read_line(channel, &buffer_recv,&len,NULL,NULL);
        // 错误情况
        if(ret == G_IO_STATUS_ERROR){
            g_error ("Error reading: %s\n", error->message);
           // g_object_unref(data);
            continue;
        }
        else if (ret == G_IO_STATUS_EOF) {
            g_print("client finished\n");
            continue;
        }
            //user add*********
        else{
            if(len > 0)
                if('\n' == buffer_recv[len - 1])
                    buffer_recv[len - 1] = '\0';

            if(!room){  // 未获得房间信息
                printf("it is very strange?????\n");
            }
            else
            {
                printf("parse remote data begin\n");
                rval = parse_remote_data(agent,_stream_id, 1, buffer_recv);
            }
            if (rval == EXIT_SUCCESS) {
                printf("parse remote date success!!!\n");
		    g_free (buffer_recv);
                break;
            } else {
                fprintf(stderr, "ERROR: failed to parse remote data\n");
                printf("Enter remote data (single line, no wrapping):\n");
                //重发
            }
        }
    }

    end:
    if(connection)
       g_object_unref(connection);
    if(channel)
        g_io_channel_unref(channel);
    printf("free \n");
    if(local_ufrag)
        g_free(local_ufrag);
    printf("free \n");
    if (local_password)
        g_free(local_password);
    printf("free \n");
    if (cands)
        g_slist_free_full(cands, (GDestroyNotify)&nice_candidate_free);
    printf("free \n");
    //if(buffer_recv)
       // g_free(buffer_recv);
    printf("free \n");
    //if(buffer_send)
      //  g_free(buffer_send);
    return 1;
}
static int
communicate_signaling(NiceAgent *agent, guint _stream_id,guint component_id)
{

    gchar *local_ufrag = NULL;  //本地用户名
    gchar *local_password = NULL;   //本地密码
    gchar ipaddr[INET6_ADDRSTRLEN]; //
    GSList *cands = NULL, *item;    //
    GSocketClient * client = NULL;
    GError *error = NULL;
    GOutputStream * out_stream = NULL;
    gssize ret_int = 0;
    char *buffer_recv = NULL;
    char buffer_send[1024] = {0};
    gsize len =0;
    GSocketConnection * connection = NULL;
    GSocket *socket = NULL;
    GIOChannel *channel = NULL;
    gint fd = 0;
    GIOStatus ret = 0;
    char * bf;
    gsize total_len;
    int rval;
    GIOFlags flags;

	
    //获取账号密码
    if (!nice_agent_get_local_credentials(agent, _stream_id,
                                          &local_ufrag, &local_password))
        goto end;
    //获取candidates
    cands = nice_agent_get_local_candidates(agent, _stream_id, component_id);
    if (cands == NULL)
        goto end;
    //建立tcp连接
    client = g_socket_client_new();
    connection = g_socket_client_connect_to_host (client,signaling_addr,signaling_port,NULL,&error);
    if (error){
	g_error("connect signaling server failed, please try the manual method");
        g_error("Error: %s\n", error->message);
	exit(1);
    }else{
        g_message("Connected with signaling ！");
    }
    out_stream = g_io_stream_get_output_stream(G_IO_STREAM(connection));

    socket = g_socket_connection_get_socket(connection);
    fd = g_socket_get_fd(socket);
    channel = g_io_channel_unix_new(fd);
    flags = g_io_channel_get_flags (channel);
      g_io_channel_set_flags (channel, flags & ~G_IO_FLAG_NONBLOCK, NULL);
    if(!channel)
    {
        goto end;
    }
    //请求房间
   
    bf = buffer_send;
    //先是用户名密码
    len = sprintf(bf,"REQUEST\n%s %s", local_ufrag, local_password);
    total_len = len;
    for (item = cands; item; item = item->next) {
        NiceCandidate *c = (NiceCandidate *)item->data;

        nice_address_to_string(&c->addr, ipaddr);
        bf = bf + len;
        len = sprintf(bf," %s,%u,%s,%u,%s",
                      c->foundation,
                      c->priority,
                      ipaddr,
                      nice_address_get_port(&c->addr),
                      candidate_type_name[c->type]);
        total_len = total_len + len;
        // (foundation),(prio),(addr),(port),(type)
    }
    len = sprintf(bf+len,"\n");
    total_len = total_len + len;
    printf("send is :%s", buffer_send);
    ret_int = g_output_stream_write(out_stream, buffer_send,total_len , NULL, NULL);
    g_output_stream_flush(out_stream, NULL, NULL);

    if((unsigned int)ret_int == total_len)
    {
        g_message("writen the request message and candidate");
    }else if(ret_int < 1)
    {
        g_error("write error");
    }
    else
        g_error("write less than request");

    //得到房间号
    printf("waiting for the room number.....\n");
    if(buffer_recv) {
	g_free(buffer_recv);
	buffer_recv = NULL;
    }
    while(!room)
    {
       	 ret = g_io_channel_read_line(channel, &buffer_recv,&len,NULL,&error);
        // ****错误情况
	printf("recv a message : %s\n",buffer_recv);
        if(ret == G_IO_STATUS_ERROR){
            g_error ("Error reading: %s\n", error->message);
           // g_object_unref(data);
            continue;
        }
        else if (ret == G_IO_STATUS_EOF) {
            g_print("client finished\n");
            continue;
        }
        // **********
        else{
            if(len > 0)
                if('\n' == buffer_recv[len - 1])
                    buffer_recv[len - 1] = '\0';

            if(!room){  // 未获得房间信息
                if(!strncmp(buffer_recv,"ROOM:",5)){
                    room = buffer_recv;
                    printf("we got a room ! %s\n",room);
                }
                else {
                    g_print("recv a message but i have not get a room number\n");
                    continue;
                }
            }
        }
    }
    g_output_stream_flush(out_stream, NULL, NULL);
    printf("buffer:%s",buffer_recv);

    //等待对方的candidate
   
    printf("waiting for the remote candidate.....\n");
    if(buffer_recv) {
	    g_free(buffer_recv);
	    buffer_recv = NULL;
    }
    while(1)
    {
	buffer_recv = NULL;   
        ret = g_io_channel_read_line(channel, &buffer_recv,&len,NULL,NULL);
        // ****错误情况
        if(ret == G_IO_STATUS_ERROR){
            g_error ("Error reading: %s\n", error->message);
           // g_object_unref(data);
            continue;
        }
        else if (ret == G_IO_STATUS_EOF) {
            g_print("client finished\n");
            continue;
        }
            // **********
        else{
            if(len > 0)
                if('\n' == buffer_recv[len - 1])
                    buffer_recv[len - 1] = '\0';

            if(!room){  // 未获得房间信息
                printf("it is very strange?????\n");
            }
            else
            {
                printf("parse remote data begin: %s\n",buffer_recv);
                rval = parse_remote_data(agent,_stream_id, 1, buffer_recv);
            }
            if (rval == EXIT_SUCCESS) {
                printf("parse success !!!\n");
		    g_free (buffer_recv);
                break;
            } else {
                fprintf(stderr, "ERROR: failed to parse remote data\n");
                printf("Enter remote data (single line, no wrapping):\n");
                
		//重发
            }
        }
    }

    end:
    if(connection)
       g_object_unref(connection);
    printf("free\n");
    if(channel)
        g_io_channel_unref(channel);
    printf("free\n");
    if(local_ufrag)
        g_free(local_ufrag);
    printf("free\n");
    if (local_password)
        g_free(local_password);
    printf("free\n");
    if (cands)
        g_slist_free_full(cands, (GDestroyNotify)&nice_candidate_free);
    printf("free\n");
    //if(buffer_recv)
     //   g_free(buffer_recv);
    printf("free\n");
    //if(buffer_send)
    //	g_free(buffer_send);
    return 1;
}*/
