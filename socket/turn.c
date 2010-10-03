/*
 * This file is part of the Nice GLib ICE library.
 *
 * (C) 2008 Collabora Ltd.
 *  Contact: Youness Alaoui
 * (C) 2008 Nokia Corporation
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
 * The Original Code is the Nice GLib ICE library.
 *
 * The Initial Developers of the Original Code are Collabora Ltd and Nokia
 * Corporation. All Rights Reserved.
 *
 * Contributors:
 *   Youness Alaoui, Collabora Ltd.
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
 * Implementation of TURN
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

#include "turn.h"
#include "stun/stunagent.h"
#include "stun/usages/timer.h"
#include "agent-priv.h"

#define STUN_END_TIMEOUT 8000
#define STUN_MAX_MS_REALM_LEN 128 // as defined in [MS-TURN]
#define STUN_PERMISSION_TIMEOUT 240 /* 300-60 s */
#define STUN_BINDING_TIMEOUT 540 /* 600-60 s */

typedef struct {
  StunMessage message;
  uint8_t buffer[STUN_MAX_MESSAGE_SIZE];
  StunTimer timer;
} TURNMessage;

typedef struct {
  NiceAddress peer;
  uint16_t channel;
} ChannelBinding;

typedef struct {
  NiceAgent *nice;
  StunAgent agent;
  GList *channels;
  GList *pending_bindings;
  ChannelBinding *current_binding;
  TURNMessage *current_binding_msg;
  TURNMessage *current_create_permission_msg;
  GSource *tick_source_channel_bind;
  GSource *tick_source_create_permission;
  NiceSocket *base_socket;
  NiceAddress server_addr;
  uint8_t *username;
  size_t username_len;
  uint8_t *password;
  size_t password_len;
  NiceTurnSocketCompatibility compatibility;
  GQueue *send_requests;
  uint8_t ms_realm[STUN_MAX_MS_REALM_LEN + 1];
  uint8_t ms_connection_id[20];
  uint32_t ms_sequence_num;
  bool ms_connection_id_valid;
  GHashTable *permissions;		/* stores installed permissions */
  GHashTable *sent_permissions; /* ongoing permission installed */
  GHashTable *send_data_queues; /* stores a send data queue for per peer */
  guint permission_timeout_source;	/* timer used to invalidate permissions */
  gboolean has_binding;
  gboolean sent_binding;
  guint binding_timeout_source;
} TurnPriv;


typedef struct {
  StunTransactionId id;
  GSource *source;
  TurnPriv *priv;
} SendRequest;

/* used to store data sent while obtaining a permission */
typedef struct {
  gchar *data;
  guint data_len;
} SendData;

static void socket_close (NiceSocket *sock);
static gint socket_recv (NiceSocket *sock, NiceAddress *from,
    guint len, gchar *buf);
static gboolean socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf);
static gboolean socket_is_reliable (NiceSocket *sock);

static void priv_process_pending_bindings (TurnPriv *priv);
static gboolean priv_retransmissions_tick_unlocked (TurnPriv *priv);
static gboolean priv_retransmissions_tick (gpointer pointer);
static void priv_schedule_tick (TurnPriv *priv);
static void priv_send_turn_message (TurnPriv *priv, TURNMessage *msg);
static gboolean priv_send_create_permission (TurnPriv *priv,
    uint8_t *realm, gsize realm_len, uint8_t *nonce, gsize nonce_len,
    const NiceAddress *peer);
static gboolean priv_send_channel_bind (TurnPriv *priv,  StunMessage *resp,
    uint16_t channel, const NiceAddress *peer);
static gboolean priv_add_channel_binding (TurnPriv *priv, const NiceAddress *peer);
static gboolean priv_forget_send_request (gpointer pointer);

static guint
priv_nice_address_hash (gconstpointer data)
{
	int *buf = (int *) data;
	size_t i;
	guint hash = 0; 
		
	for (i = 0 ; i < sizeof(NiceAddress) / sizeof(int) ; i++) {
		hash ^= g_int_hash(&buf[i]);
	}

	return hash;
}

static void
priv_send_data_queue_destroy (gpointer data)
{
	GQueue *send_queue = (GQueue *) data;
	GList *i;
	
	for (i = g_queue_peek_head_link (send_queue); i; i = i->next) {
    	SendData *data = (SendData *) i->data;

		g_free (data->data);
		g_slice_free (SendData, data);
  	}
 	g_queue_free (send_queue);
}

NiceSocket *
nice_turn_socket_new (NiceAgent *agent, NiceAddress *addr,
    NiceSocket *base_socket, NiceAddress *server_addr,
    gchar *username, gchar *password, NiceTurnSocketCompatibility compatibility)
{
  TurnPriv *priv = g_new0 (TurnPriv, 1);
  NiceSocket *sock = g_slice_new0 (NiceSocket);

  if (!sock) {
    return NULL;
  }

  if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
      compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
    stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC5389,
        STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS); 
  } else if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_MSN) {
    stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_NO_INDICATION_AUTH);
  } else if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
    stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_RFC3489,
        STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_IGNORE_CREDENTIALS);
  } else if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
      stun_agent_init (&priv->agent, STUN_ALL_KNOWN_ATTRIBUTES,
        STUN_COMPATIBILITY_OC2007,
        STUN_AGENT_USAGE_NO_INDICATION_AUTH |
        STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS |
        STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES);
  }

  priv->nice = agent;
  priv->channels = NULL;
  priv->current_binding = NULL;
  priv->base_socket = base_socket;

  if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_MSN ||
      compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
    priv->username = g_base64_decode (username, &priv->username_len);
    priv->password = g_base64_decode (password, &priv->password_len);
  } else {
    priv->username = (uint8_t *)g_strdup (username);
    priv->username_len = (size_t) strlen (username);
    if (compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
      priv->password = NULL;
      priv->password_len = 0;
    } else {
      priv->password = (uint8_t *)g_strdup (password);
      priv->password_len = (size_t) strlen (password);
    }
  }
  priv->server_addr = *server_addr;
  priv->compatibility = compatibility;
  priv->send_requests = g_queue_new ();
  priv->permissions =
		g_hash_table_new_full (priv_nice_address_hash ,
		                       (GEqualFunc) nice_address_equal , 
		                       (GDestroyNotify) nice_address_free, NULL);
  priv->sent_permissions =
		g_hash_table_new_full (priv_nice_address_hash ,
		                       (GEqualFunc) nice_address_equal , 
		                       (GDestroyNotify) nice_address_free, NULL);
  priv->send_data_queues =
		g_hash_table_new_full (priv_nice_address_hash,
		                       (GEqualFunc) nice_address_equal, 
		                       (GDestroyNotify) nice_address_free,
		                       priv_send_data_queue_destroy); 
  sock->addr = *addr;
  sock->fileno = base_socket->fileno;
  sock->send = socket_send;
  sock->recv = socket_recv;
  sock->is_reliable = socket_is_reliable;
  sock->close = socket_close;
  sock->priv = (void *) priv;
  return sock;
}



static void
socket_close (NiceSocket *sock)
{
  TurnPriv *priv = (TurnPriv *) sock->priv;
  GList *i = NULL;

  for (i = priv->channels; i; i = i->next) {
    ChannelBinding *b = i->data;
    g_free (b);
  }
  g_list_free (priv->channels);

  g_list_foreach (priv->pending_bindings, (GFunc) nice_address_free,
      NULL);
  g_list_free (priv->pending_bindings);

  if (priv->tick_source_channel_bind != NULL) {
    g_source_destroy (priv->tick_source_channel_bind);
    g_source_unref (priv->tick_source_channel_bind);
    priv->tick_source_channel_bind = NULL;
  }

  for (i = g_queue_peek_head_link (priv->send_requests); i; i = i->next) {
    SendRequest *r = i->data;
    g_source_destroy (r->source);
    g_source_unref (r->source);
    r->source = NULL;

    stun_agent_forget_transaction (&priv->agent, r->id);

    g_slice_free (SendRequest, r);

  }
  g_queue_free (priv->send_requests);

  g_hash_table_destroy (priv->permissions);
  g_hash_table_destroy (priv->send_data_queues);
  g_source_remove (priv->permission_timeout_source);
	
  g_free (priv->current_binding);
  g_free (priv->current_binding_msg);
  g_free (priv->current_create_permission_msg);
  g_free (priv->username);
  g_free (priv->password);
  g_free (priv);
}

static gint
socket_recv (NiceSocket *sock, NiceAddress *from, guint len, gchar *buf)
{
  TurnPriv *priv = (TurnPriv *) sock->priv;
  uint8_t recv_buf[STUN_MAX_MESSAGE_SIZE];
  gint recv_len;
  NiceAddress recv_from;
  NiceSocket *dummy;

  nice_debug ("received message on TURN socket");
	
  recv_len = nice_socket_recv (priv->base_socket, &recv_from,
      sizeof(recv_buf), (gchar *) recv_buf);

  if (recv_len > 0)
    return nice_turn_socket_parse_recv (sock, &dummy, from, len, buf,
        &recv_from, (gchar *) recv_buf, (guint) recv_len);
  else
    return recv_len;
}

static StunMessageReturn
stun_message_append_ms_connection_id(StunMessage *msg,
    uint8_t *ms_connection_id, uint32_t ms_sequence_num)
{
  uint8_t buf[24];

  memcpy(buf, ms_connection_id, 20);
  *(uint32_t*)(buf + 20) = htonl(ms_sequence_num);
  return stun_message_append_bytes (msg, STUN_ATTRIBUTE_MS_SEQUENCE_NUMBER,
                                    buf, 24);
}

static void
stun_message_ensure_ms_realm(StunMessage *msg, uint8_t *realm)
{
  /* With MS-TURN, original clients do not send REALM attribute in Send and Set
   * Active Destination requests, but use it to compute MESSAGE-INTEGRITY. We
   * simply append cached realm value to the message and use it in subsequent
   * stun_agent_finish_message() call. Messages with this additional attribute
   * are handled correctly on OCS Access Edge working as TURN server. */
  if (stun_message_get_method(msg) == STUN_SEND ||
      stun_message_get_method(msg) == STUN_OLD_SET_ACTIVE_DST) {
    stun_message_append_bytes (msg, STUN_ATTRIBUTE_REALM, realm,
                               strlen((char *)realm));
  }
}

static gboolean
priv_has_permission_for_peer (TurnPriv *priv, const NiceAddress *to)
{
	return g_hash_table_lookup (priv->permissions, to) != NULL;
}

static gboolean
priv_has_sent_permission_for_peer (TurnPriv *priv, const NiceAddress *to)
{
	return g_hash_table_lookup (priv->sent_permissions, to) != NULL;
}

static void
socket_enqueue_data(TurnPriv *priv, const NiceAddress *to,
	guint len, const gchar *buf)
{
	SendData *data = g_slice_new0 (SendData);
	GQueue *queue = g_hash_table_lookup (priv->send_data_queues, to);

	if (queue == NULL) {
		queue = g_queue_new ();
		g_hash_table_insert (priv->send_data_queues, nice_address_dup (to),
		                     queue);
	}
	
	data->data = g_memdup(buf, len);
	data->data_len = len;
	g_queue_push_tail (queue, data);
}

static void
socket_dequeue_all_data (TurnPriv *priv, const NiceAddress *to)
{
	GQueue *send_queue = g_hash_table_lookup (priv->send_data_queues, to);
	
	if (send_queue) {
		while (!g_queue_is_empty (send_queue)) {
			SendData *data =
				(SendData *) g_queue_pop_head(send_queue);

			nice_debug("dequeing data enqueued when installing permission or binding");
			nice_socket_send (priv->base_socket, to, data->data_len, data->data);

			g_free (data->data);
			g_slice_free (SendData, data);
		}

		/* remove queue from table */
		g_hash_table_remove (priv->send_data_queues, to);
	}
}


static gboolean
socket_send (NiceSocket *sock, const NiceAddress *to,
    guint len, const gchar *buf)
{
  TurnPriv *priv = (TurnPriv *) sock->priv;
  StunMessage msg;
  uint8_t buffer[STUN_MAX_MESSAGE_SIZE];
  size_t msg_len;
  struct sockaddr_storage sa;
  GList *i = priv->channels;
  ChannelBinding *binding = NULL;

  for (; i; i = i->next) {
    ChannelBinding *b = i->data;
    if (nice_address_equal (&b->peer, to)) {
      binding = b;
      break;
    }
  }
	
  nice_address_copy_to_sockaddr (to, (struct sockaddr *)&sa);

  if (binding) {
    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
      if (len + sizeof(uint32_t) <= sizeof(buffer)) {
        uint16_t len16 = htons ((uint16_t) len);
        uint16_t channel16 = htons (binding->channel);
        memcpy (buffer, &channel16, sizeof(uint16_t));
        memcpy (buffer + sizeof(uint16_t), &len16,sizeof(uint16_t));
        memcpy (buffer + sizeof(uint32_t), buf, len);
        msg_len = len + sizeof(uint32_t);
      } else {
        return 0;
      }
    } else {
      return nice_socket_send (priv->base_socket, &priv->server_addr, len, buf);
    }
  } else {
	nice_debug("no binding");
    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
      if (!stun_agent_init_indication (&priv->agent, &msg,
              buffer, sizeof(buffer), STUN_IND_SEND))
        goto send;
      if (stun_message_append_xor_addr (&msg, STUN_ATTRIBUTE_PEER_ADDRESS,
              (struct sockaddr *)&sa, sizeof(sa)) !=
          STUN_MESSAGE_RETURN_SUCCESS)
        goto send;
    } else {
      if (!stun_agent_init_request (&priv->agent, &msg,
              buffer, sizeof(buffer), STUN_SEND))
        goto send;

      if (stun_message_append32 (&msg, STUN_ATTRIBUTE_MAGIC_COOKIE,
              TURN_MAGIC_COOKIE) != STUN_MESSAGE_RETURN_SUCCESS)
        goto send;
      if (priv->username != NULL && priv->username_len > 0) {
        if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_USERNAME,
                priv->username, priv->username_len) !=
            STUN_MESSAGE_RETURN_SUCCESS)
          goto send;
      }
      if (stun_message_append_addr (&msg, STUN_ATTRIBUTE_DESTINATION_ADDRESS,
              (struct sockaddr *)&sa, sizeof(sa)) != STUN_MESSAGE_RETURN_SUCCESS)
        goto send;

      if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE &&
          priv->current_binding &&
          nice_address_equal (&priv->current_binding->peer, to)) {
        stun_message_append32 (&msg, STUN_ATTRIBUTE_OPTIONS, 1);
      }
    }

    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
      stun_message_append32(&msg, STUN_ATTRIBUTE_MS_VERSION, 1);

      if (priv->ms_connection_id_valid)
        stun_message_append_ms_connection_id(&msg, priv->ms_connection_id,
            ++priv->ms_sequence_num);

      stun_message_ensure_ms_realm(&msg, priv->ms_realm);
    }

    if (stun_message_append_bytes (&msg, STUN_ATTRIBUTE_DATA,
            buf, len) != STUN_MESSAGE_RETURN_SUCCESS)
      goto send;

    msg_len = stun_agent_finish_message (&priv->agent, &msg,
        priv->password, priv->password_len);
    if (msg_len > 0 && stun_message_get_class (&msg) == STUN_REQUEST) {
      SendRequest *req = g_slice_new0 (SendRequest);

      req->priv = priv;
      stun_message_id (&msg, req->id);
      req->source = agent_timeout_add_with_context (priv->nice, STUN_END_TIMEOUT,
          priv_forget_send_request, req);
      g_queue_push_tail (priv->send_requests, req);
    }
  }

  if (msg_len > 0) {
	if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
	  if (!priv_has_permission_for_peer (priv, to) &&
	      !priv_has_sent_permission_for_peer (priv, to)) {
		  nice_debug ("no permission installed for peer");
		  priv_send_create_permission(priv, NULL, 0, NULL, 0, to);
	  }
	}

	if (!priv->has_binding && !priv->sent_binding && binding) {
		nice_debug("renewing channel binding");
		priv_send_channel_bind  (priv, NULL, binding->channel, to);
	}

	if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766 &&
	     !priv_has_permission_for_peer (priv, to)) {
		/* enque data */
		nice_debug("enqueing data to be sent when aquiring permission or binding");
		socket_enqueue_data(priv, to, msg_len, (gchar *)buffer);
		return TRUE;	
	} else {
		return nice_socket_send (priv->base_socket, &priv->server_addr,
        	msg_len, (gchar *)buffer);
	}
  }
 send:
  	return nice_socket_send (priv->base_socket, to, len, buf);
}

static gboolean
socket_is_reliable (NiceSocket *sock)
{
  TurnPriv *priv = (TurnPriv *) sock->priv;
  return nice_socket_is_reliable (priv->base_socket);
}

static gboolean
priv_forget_send_request (gpointer pointer)
{
  SendRequest *req = pointer;

  agent_lock ();

  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in turn.c:priv_forget_send_request");
    agent_unlock ();
    return FALSE;
  }

  stun_agent_forget_transaction (&req->priv->agent, req->id);

  g_queue_remove (req->priv->send_requests, req);

  g_source_destroy (req->source);
  g_source_unref (req->source);
  req->source = NULL;

  agent_unlock ();

  g_slice_free (SendRequest, req);

  return FALSE;
}

static gboolean
priv_permission_timeout (gpointer data)
{
	TurnPriv *priv = (TurnPriv *) data;

	nice_debug ("Permission is about to timeout, schedule renewal");
	
	agent_lock ();
	/* remove all permissions for this agent (the permission for the peer
	   we are sending to will be renewed) */
	g_hash_table_remove_all (priv->permissions);
	agent_unlock ();

	return TRUE;
}

static gboolean
priv_binding_timeout (gpointer data)
{
	TurnPriv *priv = (TurnPriv *) data;

	nice_debug ("Permission is about to timeout, schedule renewal");
	
	agent_lock ();
	priv->has_binding = FALSE;
	agent_unlock ();

	return TRUE;
}

gint
nice_turn_socket_parse_recv (NiceSocket *sock, NiceSocket **from_sock,
  NiceAddress *from, guint len, gchar *buf,
  NiceAddress *recv_from, gchar *recv_buf, guint recv_len)
{

  TurnPriv *priv = (TurnPriv *) sock->priv;
  StunValidationStatus valid;
  StunMessage msg;
  struct sockaddr_storage sa;
  socklen_t from_len = sizeof (sa);
  GList *i = priv->channels;
  ChannelBinding *binding = NULL;

  if (nice_address_equal (&priv->server_addr, recv_from)) {
    valid = stun_agent_validate (&priv->agent, &msg,
        (uint8_t *) recv_buf, (size_t) recv_len, NULL, NULL);

    if (valid == STUN_VALIDATION_SUCCESS) {
      if (priv->compatibility != NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 &&
          priv->compatibility != NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
        uint32_t cookie;
        if (stun_message_find32 (&msg, STUN_ATTRIBUTE_MAGIC_COOKIE,
                &cookie) != STUN_MESSAGE_RETURN_SUCCESS)
          goto recv;
        if (cookie != TURN_MAGIC_COOKIE)
          goto recv;
      }

      if (stun_message_get_method (&msg) == STUN_SEND) {
        if (stun_message_get_class (&msg) == STUN_RESPONSE) {
          SendRequest *req = NULL;
          GList *i = g_queue_peek_head_link (priv->send_requests);
          StunTransactionId msg_id;

          stun_message_id (&msg, msg_id);

          for (; i; i = i->next) {
            SendRequest *r = i->data;
            if (memcmp (&r->id, msg_id, sizeof(StunTransactionId)) == 0) {
              req = r;
              break;
            }
          }

          if (req) {
            g_source_destroy (req->source);
            g_source_unref (req->source);
            req->source = NULL;

            g_queue_remove (priv->send_requests, req);

            g_slice_free (SendRequest, req);
          }

          if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
            uint32_t opts = 0;
            if (stun_message_find32 (&msg, STUN_ATTRIBUTE_OPTIONS, &opts) ==
                STUN_MESSAGE_RETURN_SUCCESS && opts & 0x1)
              goto msn_google_lock;
          }
        }
        return 0;
      } else if (stun_message_get_method (&msg) == STUN_OLD_SET_ACTIVE_DST) {
        StunTransactionId request_id;
        StunTransactionId response_id;
        if (priv->current_binding && priv->current_binding_msg) {
          stun_message_id (&msg, response_id);
          stun_message_id (&priv->current_binding_msg->message, request_id);
          if (memcmp (request_id, response_id, sizeof(StunTransactionId)) == 0) {
            g_free (priv->current_binding_msg);
            priv->current_binding_msg = NULL;

            if (stun_message_get_class (&msg) == STUN_RESPONSE &&
                (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_MSN ||
                 priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007)) {
              goto msn_google_lock;
            } else {
              g_free (priv->current_binding);
              priv->current_binding = NULL;
            }
          }
        }

        return 0;
      } else if (stun_message_get_method (&msg) == STUN_CHANNELBIND) {
        StunTransactionId request_id;
        StunTransactionId response_id;
					 
        if (priv->current_binding_msg) {
          stun_message_id (&msg, response_id);
          stun_message_id (&priv->current_binding_msg->message, request_id);
          if (memcmp (request_id, response_id, sizeof(StunTransactionId)) == 0) {
			if (stun_message_get_class (&msg) == STUN_ERROR) {
              int code = -1;
			  uint8_t *sent_realm = NULL;
              uint8_t *recv_realm = NULL;
              uint16_t sent_realm_len = 0;
              uint16_t recv_realm_len = 0;
				
              sent_realm = (uint8_t *) stun_message_find (
                &priv->current_binding_msg->message,
                STUN_ATTRIBUTE_REALM, &sent_realm_len);
              recv_realm = (uint8_t *) stun_message_find (&msg,
                STUN_ATTRIBUTE_REALM, &recv_realm_len);

			  if (!priv->has_binding) {
				  nice_debug ("sent realm: %s\n", sent_realm);
				  nice_debug ("recv realm: %s\n", recv_realm);
			  }
				
              /* check for unauthorized error response */
              if (stun_message_find_error (&msg, &code) ==
                  STUN_MESSAGE_RETURN_SUCCESS &&
                  (code == 438 || (code == 401 &&
                   !(recv_realm != NULL &&
                       recv_realm_len > 0 &&
                       recv_realm_len == sent_realm_len &&
                       sent_realm != NULL &&
                       memcmp (sent_realm, recv_realm, sent_realm_len) == 0)))) {
                
                if (priv->current_binding) {
				  g_free (priv->current_binding_msg);
                  priv->current_binding_msg = NULL;
                  priv_send_channel_bind (priv, &msg,
                      priv->current_binding->channel,
                      &priv->current_binding->peer);
                } else {
					/* look up binding associated with peer */
					GList *i = priv->channels;
  					ChannelBinding *binding = NULL;
					struct sockaddr sa;
					socklen_t sa_len = sizeof(sa);
					NiceAddress to;
					
					stun_message_find_xor_addr (&priv->current_binding_msg->message,
		                             STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &sa,
		                             &sa_len);
					nice_address_set_from_sockaddr (&to, &sa);
					
  					for (; i; i = i->next) {
    					ChannelBinding *b = i->data;
    					if (nice_address_equal (&b->peer, &to)) {
      						binding = b;
      						break;
    					}
  					}

					g_free (priv->current_binding_msg);
                	priv->current_binding_msg = NULL;
					
					if (binding)
						priv_send_channel_bind (priv, &msg, binding->channel, &to);
				}
			  } else {
                g_free (priv->current_binding);
                priv->current_binding = NULL;
                g_free (priv->current_binding_msg);
                priv->current_binding_msg = NULL;
                priv_process_pending_bindings (priv);
              }
            } else if (stun_message_get_class (&msg) == STUN_RESPONSE) {
              g_free (priv->current_binding_msg);
              priv->current_binding_msg = NULL;
			  priv->has_binding = TRUE;
			  priv->sent_binding = FALSE;
              if (priv->current_binding) {
                priv->channels = g_list_append (priv->channels,
                    priv->current_binding);
                priv->current_binding = NULL;
              }
              priv_process_pending_bindings (priv);

			  /* install timer to schedule refresh of the permission */
			  if (!priv->binding_timeout_source) {
				priv->binding_timeout_source =
				 	g_timeout_add_seconds (STUN_BINDING_TIMEOUT,
				                priv_binding_timeout, priv);
			  }
            }
          }
        }
        return 0;
	  } else if (stun_message_get_method (&msg) == STUN_CREATEPERMISSION) {
		StunTransactionId request_id;
        StunTransactionId response_id;

		if (priv->current_create_permission_msg) {
			stun_message_id (&msg, response_id);
          	stun_message_id (&priv->current_create_permission_msg->message, request_id);

			if (memcmp (request_id, response_id, sizeof(StunTransactionId)) == 0) {
		 		struct sockaddr peer;
		 		socklen_t peer_len = sizeof(peer);
				int code = -1;
				NiceAddress *to = nice_address_new ();;
				
		 		nice_debug("got response for CreatePermission");
		 		stun_message_find_xor_addr (&priv->current_create_permission_msg->message,
		                             STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &peer,
		                             &peer_len);
				nice_address_set_from_sockaddr (to, &peer);
				
		 		g_free (priv->current_create_permission_msg);
		 		priv->current_create_permission_msg = NULL;

				/* unathorized => resend with realm and nonce) */
			 	if (stun_message_get_class (&msg) == STUN_ERROR &&
				     stun_message_find_error (&msg, &code) ==
                  		STUN_MESSAGE_RETURN_SUCCESS &&
                  		(code == 438 || (code == 401))) {
					uint8_t *recv_realm = NULL;
        			uint16_t recv_realm_len = 0;
	 				uint8_t *recv_nonce = NULL;
					uint16_t recv_nonce_len = 0;
			 
        			recv_realm = (uint8_t *) stun_message_find (&msg,
          				STUN_ATTRIBUTE_REALM, &recv_realm_len);
					recv_nonce = (uint8_t *) stun_message_find (&msg,
		  				STUN_ATTRIBUTE_NONCE, &recv_nonce_len);
			 
					nice_debug("got realm: %s", recv_realm);
					nice_debug("got nonce: %s", recv_nonce);

					/* resend CreatePermission */
					priv_send_create_permission (priv, recv_realm, recv_realm_len,
			    			recv_nonce, recv_nonce_len, to);
					nice_address_free (to);
		 		} else {
		 			/* we now have a permission installed for this peer */
					g_hash_table_insert (priv->permissions, to, to);
					g_hash_table_remove (priv->sent_permissions, to);

					/* install timer to schedule refresh of the permission */
					/* (will not schedule refresh if we got an error) */
					if (stun_message_get_class (&msg) == STUN_RESPONSE &&
					    !priv->permission_timeout_source) {
						priv->permission_timeout_source =
				 			g_timeout_add_seconds (STUN_PERMISSION_TIMEOUT,
				                priv_permission_timeout, priv);
					}

					/* send enqued data */
				 	nice_debug("about to dequeue data");
					socket_dequeue_all_data (priv, to);
				 } 
			}	
		 }

		 return 0;
	  } else if (stun_message_get_class (&msg) == STUN_INDICATION &&
          stun_message_get_method (&msg) == STUN_IND_DATA) {
        uint16_t data_len;
        uint8_t *data;

        if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
            priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
          if (stun_message_find_xor_addr (&msg, STUN_ATTRIBUTE_REMOTE_ADDRESS,
                  (struct sockaddr *)&sa, &from_len) !=
              STUN_MESSAGE_RETURN_SUCCESS)
            goto recv;
        } else {
          if (stun_message_find_addr (&msg, STUN_ATTRIBUTE_REMOTE_ADDRESS,
                  (struct sockaddr *)&sa, &from_len) !=
              STUN_MESSAGE_RETURN_SUCCESS)
            goto recv;
        }

        data = (uint8_t *) stun_message_find (&msg, STUN_ATTRIBUTE_DATA,
            &data_len);

        if (data == NULL)
          goto recv;

        nice_address_set_from_sockaddr (from, (struct sockaddr *)&sa);

        *from_sock = sock;
        memmove (buf, data, len > data_len ? data_len : len);
        return len > data_len ? data_len : len;
      } else {
        goto recv;
      }
	}
  }

 recv:
  for (i = priv->channels; i; i = i->next) {
    ChannelBinding *b = i->data;
    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
        priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
      if (b->channel == ntohs(((uint16_t *)recv_buf)[0])) {
        recv_len = ntohs (((uint16_t *)recv_buf)[1]);
        recv_buf += sizeof(uint32_t);
        binding = b;
        break;
      }
    } else {
      binding = b;
      break;
    }
  }

  if (binding) {
    *from = binding->peer;
    *from_sock = sock;
  } else {
    *from = *recv_from;
  }
		
  memmove (buf, recv_buf, len > recv_len ? recv_len : len);
  return len > recv_len ? recv_len : len;

 msn_google_lock:

  if (priv->current_binding) {
    GList *i = priv->channels;
    for (; i; i = i->next) {
      ChannelBinding *b = i->data;
      g_free (b);
    }
    g_list_free (priv->channels);
    priv->channels = g_list_append (NULL, priv->current_binding);
    priv->current_binding = NULL;
    priv_process_pending_bindings (priv);
  }

  return 0;
}

gboolean
nice_turn_socket_set_peer (NiceSocket *sock, NiceAddress *peer)
{
  TurnPriv *priv = (TurnPriv *) sock->priv;

  return priv_add_channel_binding (priv, peer);
}

static void
priv_process_pending_bindings (TurnPriv *priv)
{
  gboolean ret = FALSE;
  while (priv->pending_bindings != NULL && ret == FALSE) {
    NiceAddress *peer = priv->pending_bindings->data;
    ret = priv_add_channel_binding (priv, peer);
    priv->pending_bindings = g_list_remove (priv->pending_bindings, peer);
    nice_address_free (peer);
  }
}


static gboolean
priv_retransmissions_tick_unlocked (TurnPriv *priv)
{
  if (priv->current_binding_msg) {
    switch (stun_timer_refresh (&priv->current_binding_msg->timer)) {
      case STUN_USAGE_TIMER_RETURN_TIMEOUT:
        {
          /* Time out */
          StunTransactionId id;

          stun_message_id (&priv->current_binding_msg->message, id);
          stun_agent_forget_transaction (&priv->agent, id);

          g_free (priv->current_binding);
          priv->current_binding = NULL;
          g_free (priv->current_binding_msg);
          priv->current_binding_msg = NULL;


          priv_process_pending_bindings (priv);
          break;
        }
      case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
        /* Retransmit */
        nice_socket_send (priv->base_socket, &priv->server_addr,
            stun_message_length (&priv->current_binding_msg->message),
            (gchar *)priv->current_binding_msg->buffer);
        break;
      case STUN_USAGE_TIMER_RETURN_SUCCESS:
        break;
    }
  }

  priv_schedule_tick (priv);
  return FALSE;
}

static gboolean
priv_retransmissions_create_permission_tick_unlocked (TurnPriv *priv)
{
  if (priv->current_create_permission_msg) {
    switch (stun_timer_refresh (&priv->current_create_permission_msg->timer)) {
      case STUN_USAGE_TIMER_RETURN_TIMEOUT:
        {
          /* Time out */
          StunTransactionId id;
		  NiceAddress *to = nice_address_new ();
		  struct sockaddr addr;
		  socklen_t addr_len = sizeof(addr);

          stun_message_id (&priv->current_create_permission_msg->message, id);
          stun_agent_forget_transaction (&priv->agent, id);
		  stun_message_find_xor_addr (&priv->current_create_permission_msg->message,
		                              STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &addr,
		                              &addr_len);
		  nice_address_set_from_sockaddr (to, &addr);
			
          g_free (priv->current_create_permission_msg);
          priv->current_create_permission_msg = NULL;

		  /* we got a timeout when retransmitting a CreatePermission
			 message, assume we can just send the data, the server
			 might not support RFC TURN, or connectivity check will
			 fail eventually anyway */
		  g_hash_table_insert (priv->permissions, to, to);
		  g_hash_table_remove (priv->sent_permissions, to);

		  socket_dequeue_all_data (priv, to);
		
          break;
        }
      case STUN_USAGE_TIMER_RETURN_RETRANSMIT:
        /* Retransmit */
        nice_socket_send (priv->base_socket, &priv->server_addr,
            stun_message_length (&priv->current_create_permission_msg->message),
            (gchar *)priv->current_create_permission_msg->buffer);
        break;
      case STUN_USAGE_TIMER_RETURN_SUCCESS:
        break;
    }
  }

  priv_schedule_tick (priv);
  return FALSE;
}

static gboolean
priv_retransmissions_tick (gpointer pointer)
{
  TurnPriv *priv = pointer;
  gboolean ret;

  agent_lock ();
  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in turn.c:priv_retransmissions_tick");
    agent_unlock ();
    return FALSE;
  }

  ret = priv_retransmissions_tick_unlocked (priv);
  if (ret == FALSE) {
    if (priv->tick_source_channel_bind != NULL) {
      g_source_destroy (priv->tick_source_channel_bind);
      g_source_unref (priv->tick_source_channel_bind);
      priv->tick_source_channel_bind = NULL;
    }
  }
  agent_unlock ();

  return ret;
}

static gboolean
priv_retransmissions_create_permission_tick (gpointer pointer)
{
  TurnPriv *priv = pointer;
  gboolean ret;

  agent_lock ();
  if (g_source_is_destroyed (g_main_current_source ())) {
    nice_debug ("Source was destroyed. "
        "Avoided race condition in turn.c:priv_retransmissions_create_permission_tick");
    agent_unlock ();
    return FALSE;
  }

  ret = priv_retransmissions_create_permission_tick_unlocked (priv);
  if (ret == FALSE) {
    if (priv->tick_source_create_permission != NULL) {
      g_source_destroy (priv->tick_source_create_permission);
      g_source_unref (priv->tick_source_create_permission);
      priv->tick_source_create_permission = NULL;
    }
  }
  agent_unlock ();

  return ret;
}

static void
priv_schedule_tick (TurnPriv *priv)
{
  if (priv->tick_source_channel_bind != NULL) {
    g_source_destroy (priv->tick_source_channel_bind);
    g_source_unref (priv->tick_source_channel_bind);
    priv->tick_source_channel_bind = NULL;
  }

  if (priv->current_binding_msg) {
    guint timeout = stun_timer_remainder (&priv->current_binding_msg->timer);
    if (timeout > 0) {
      priv->tick_source_channel_bind =
          agent_timeout_add_with_context (priv->nice, timeout,
              priv_retransmissions_tick, priv);
    } else {
      priv_retransmissions_tick_unlocked (priv);
    }
  }

  if (priv->current_create_permission_msg) {
    guint timeout = stun_timer_remainder (&priv->current_create_permission_msg->timer);
    if (timeout > 0) {
      priv->tick_source_create_permission = agent_timeout_add_with_context (priv->nice, timeout,
          priv_retransmissions_create_permission_tick, priv);
    } else {
      priv_retransmissions_create_permission_tick_unlocked (priv);
    }
  }
}

static void
priv_send_turn_message (TurnPriv *priv, TURNMessage *msg)
{
  size_t stun_len = stun_message_length (&msg->message);

  if (priv->current_binding_msg) {
    g_free (priv->current_binding_msg);
    priv->current_binding_msg = NULL;
  }

  nice_socket_send (priv->base_socket, &priv->server_addr,
      stun_len, (gchar *)msg->buffer);

  if (nice_socket_is_reliable (priv->base_socket)) {
    stun_timer_start_reliable (&msg->timer,
        STUN_TIMER_DEFAULT_RELIABLE_TIMEOUT);
  } else {
    stun_timer_start (&msg->timer, STUN_TIMER_DEFAULT_TIMEOUT,
        STUN_TIMER_DEFAULT_MAX_RETRANSMISSIONS);
  }

  priv->current_binding_msg = msg;
  priv_schedule_tick (priv);
}

static gboolean
priv_send_create_permission(TurnPriv *priv, uint8_t *realm, gsize realm_len,
                            uint8_t *nonce, gsize nonce_len,
                            const NiceAddress *peer)
{
	guint msg_buf_len;
	gboolean res = FALSE;
	TURNMessage *msg = g_new0 (TURNMessage, 1);
	struct sockaddr addr;
	NiceAddress *to = nice_address_dup (peer);
	
	nice_debug("creating CreatePermission message");
	g_hash_table_insert (priv->sent_permissions, to, to);

	nice_address_copy_to_sockaddr (peer, &addr);
	
	/* send CreatePermission */
	msg_buf_len = stun_usage_turn_create_permission(&priv->agent, &msg->message,
		msg->buffer, sizeof(msg->buffer), priv->username, priv->username_len,
		priv->password, priv->password_len, realm, realm_len, nonce, nonce_len,
	    &addr,
		NICE_TURN_SOCKET_COMPATIBILITY_RFC5766);

	if (msg_buf_len > 0) {
		nice_debug("sending CreatePermission message, lenght: %d",
			msg_buf_len);
		res = nice_socket_send (priv->base_socket, &priv->server_addr,
		                        msg_buf_len, (gchar *) msg->buffer);
		nice_debug("sent CreatePermission message, result: %d", res);

		if (nice_socket_is_reliable (priv->base_socket)) {
    		stun_timer_start_reliable (&msg->timer);
  		} else {
    		stun_timer_start (&msg->timer);
  		}

		priv_schedule_tick (priv);
		priv->current_create_permission_msg = msg;
	} else {
		g_free(msg);
	}

	return res;
}

static gboolean
priv_send_channel_bind (TurnPriv *priv,  StunMessage *resp,
    uint16_t channel, const NiceAddress *peer)
{
  uint32_t channel_attr = channel << 16;
  size_t stun_len;
  struct sockaddr_storage sa;
  TURNMessage *msg = g_new0 (TURNMessage, 1);

  priv->sent_binding = TRUE;
  nice_address_copy_to_sockaddr (peer, (struct sockaddr *)&sa);

  if (!stun_agent_init_request (&priv->agent, &msg->message,
          msg->buffer, sizeof(msg->buffer), STUN_CHANNELBIND)) {
    g_free (msg);
    return FALSE;
  }

  if (stun_message_append32 (&msg->message, STUN_ATTRIBUTE_CHANNEL_NUMBER,
          channel_attr) != STUN_MESSAGE_RETURN_SUCCESS) {
    g_free (msg);
    return FALSE;
  }

  if (stun_message_append_xor_addr (&msg->message, STUN_ATTRIBUTE_PEER_ADDRESS,
          (struct sockaddr *)&sa, sizeof(sa)) != STUN_MESSAGE_RETURN_SUCCESS) {
    g_free (msg);
    return FALSE;
  }

  if (priv->username != NULL && priv->username_len > 0) {
    if (stun_message_append_bytes (&msg->message, STUN_ATTRIBUTE_USERNAME,
            priv->username, priv->username_len) != STUN_MESSAGE_RETURN_SUCCESS) {
      g_free (msg);
      return FALSE;
    }
  }

  if (resp) {
    uint8_t *realm;
    uint8_t *nonce;
    uint16_t len;

    realm = (uint8_t *) stun_message_find (resp, STUN_ATTRIBUTE_REALM, &len);
    if (realm != NULL) {
      if (stun_message_append_bytes (&msg->message, STUN_ATTRIBUTE_REALM,
              realm, len) != STUN_MESSAGE_RETURN_SUCCESS) {
        g_free (msg);
        return 0;
      }
    }
    nonce = (uint8_t *) stun_message_find (resp, STUN_ATTRIBUTE_NONCE, &len);
    if (nonce != NULL) {
      if (stun_message_append_bytes (&msg->message, STUN_ATTRIBUTE_NONCE,
              nonce, len) != STUN_MESSAGE_RETURN_SUCCESS) {
        g_free (msg);
        return 0;
      }
    }
  }

  stun_len = stun_agent_finish_message (&priv->agent, &msg->message,
      priv->password, priv->password_len);

  if (stun_len > 0) {
	  priv_send_turn_message (priv, msg);
    return TRUE;
  }

  g_free (msg);
  return FALSE;
}

static gboolean
priv_add_channel_binding (TurnPriv *priv, const NiceAddress *peer)
{
  size_t stun_len;
  struct sockaddr_storage sa;

  priv->sent_binding = TRUE;
  nice_address_copy_to_sockaddr (peer, (struct sockaddr *)&sa);

  if (priv->current_binding) {
    NiceAddress * pending= nice_address_new ();
    *pending = *peer;
    priv->pending_bindings = g_list_append (priv->pending_bindings, pending);
    return FALSE;
  }

  if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_DRAFT9 ||
      priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_RFC5766) {
    uint16_t channel = 0x4000;
    GList *i = priv->channels;
    for (; i; i = i->next) {
      ChannelBinding *b = i->data;
      if (channel == b->channel) {
        i = priv->channels;
        channel++;
        continue;
      }
    }

    if (channel >= 0x4000 && channel < 0xffff) {
      gboolean ret = priv_send_channel_bind (priv, NULL, channel, peer);
      if (ret) {
        priv->current_binding = g_new0 (ChannelBinding, 1);
        priv->current_binding->channel = channel;
        priv->current_binding->peer = *peer;
      }
      return ret;
    }
    return FALSE;
  } else if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_MSN ||
             priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
    TURNMessage *msg = g_new0 (TURNMessage, 1);
    if (!stun_agent_init_request (&priv->agent, &msg->message,
            msg->buffer, sizeof(msg->buffer), STUN_OLD_SET_ACTIVE_DST)) {
      g_free (msg);
      return FALSE;
    }

    if (stun_message_append32 (&msg->message, STUN_ATTRIBUTE_MAGIC_COOKIE,
            TURN_MAGIC_COOKIE) != STUN_MESSAGE_RETURN_SUCCESS) {
      g_free (msg);
      return FALSE;
    }

    if (priv->username != NULL && priv->username_len > 0) {
      if (stun_message_append_bytes (&msg->message, STUN_ATTRIBUTE_USERNAME,
            priv->username, priv->username_len) != STUN_MESSAGE_RETURN_SUCCESS) {
        g_free (msg);
        return FALSE;
      }
    }

    if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_OC2007) {
      if (priv->ms_connection_id_valid)
          stun_message_append_ms_connection_id(&msg->message,
              priv->ms_connection_id, ++priv->ms_sequence_num);

      stun_message_ensure_ms_realm(&msg->message, priv->ms_realm);
    }

    if (stun_message_append_addr (&msg->message,
            STUN_ATTRIBUTE_DESTINATION_ADDRESS,
            (struct sockaddr *)&sa, sizeof(sa)) != STUN_MESSAGE_RETURN_SUCCESS) {
      g_free (msg);
      return FALSE;
    }

    stun_len = stun_agent_finish_message (&priv->agent, &msg->message,
        priv->password, priv->password_len);

    if (stun_len > 0) {
      priv->current_binding = g_new0 (ChannelBinding, 1);
      priv->current_binding->channel = 0;
      priv->current_binding->peer = *peer;
      priv_send_turn_message (priv, msg);
      return TRUE;
    }
    g_free (msg);
    return FALSE;
  } else if (priv->compatibility == NICE_TURN_SOCKET_COMPATIBILITY_GOOGLE) {
    priv->current_binding = g_new0 (ChannelBinding, 1);
    priv->current_binding->channel = 0;
    priv->current_binding->peer = *peer;
    return TRUE;
  } else {
    return FALSE;
  }

  return FALSE;
}

void
nice_turn_socket_set_ms_realm(NiceSocket *sock, StunMessage *msg)
{
  TurnPriv *priv = (TurnPriv *)sock->priv;
  uint16_t alen;
  const uint8_t *realm = stun_message_find(msg, STUN_ATTRIBUTE_REALM, &alen);

  if (realm && alen <= STUN_MAX_MS_REALM_LEN) {
    memcpy(priv->ms_realm, realm, alen);
    priv->ms_realm[alen] = '\0';
  }
}

void
nice_turn_socket_set_ms_connection_id (NiceSocket *sock, StunMessage *msg)
{
  TurnPriv *priv = (TurnPriv *)sock->priv;
  uint16_t alen;
  const uint8_t *ms_seq_num = stun_message_find(msg,
      STUN_ATTRIBUTE_MS_SEQUENCE_NUMBER, &alen);

  if (ms_seq_num && alen == 24) {
      memcpy (priv->ms_connection_id, ms_seq_num, 20);
      priv->ms_sequence_num = ntohl((uint32_t)*(ms_seq_num + 20));
      priv->ms_connection_id_valid = TRUE;
  }
}
