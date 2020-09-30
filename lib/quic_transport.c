/*
 * quic_transport.c
 *
 *  Created on: 24 Jan 2020
 *      Author: samuelh
 */

#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "quic_transport.h"
#include "util.h"
#include "debug.h"
#include "map.h"

#define NGHQ_IS_SHORT_HEADER(b) (!(b & 0x80))
#define NGHQ_PKT_NUMLEN_MASK 0x03

#define QUIC_FRAME_PADDING 0x00ULL
#define QUIC_FRAME_PING 0x01ULL
/* ACK frames prohibited in multicast QUIC (0x02 - 0x03) */
#define QUIC_FRAME_RESET_STREAM 0x04ULL
/* STOP_SENDING, CRYPTO, NEW_TOKEN frames prohibited in multicast QUIC
 * (0x05, 0x06, 0x07) */
#define QUIC_FRAME_STREAM 0x08ULL
#define QUIC_FRAME_STREAM_FIN 0x09ULL
#define QUIC_FRAME_STREAM_LEN 0x0AULL
#define QUIC_FRAME_STREAM_LEN_FIN 0x0BULL
#define QUIC_FRAME_STREAM_OFF 0x0CULL
#define QUIC_FRAME_STREAM_OFF_FIN 0x0DULL
#define QUIC_FRAME_STREAM_OFF_LEN 0x0EULL
#define QUIC_FRAME_STREAM_OFF_LEN_FIN 0x0FULL
/* MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED, STREAM_DATA_BLOCKED,
 * STREAMS_BLOCKED, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE,
 * PATH_RESPONSE, CONNECTION_CLOSE frames prohibited in multicast QUIC
 * (0x10 - 0x1d)
 */

ssize_t _parse_stream_frame (nghq_session *ctx, uint8_t stream_type,
                             uint8_t *buf, size_t len);
ssize_t _parse_reset_stream_frame (nghq_session *ctx, uint8_t *buf, size_t len);

/* TODO: Get this from the application? */
static uint8_t _hp_mask[5] = {0, 0, 0, 0, 0};
int _transport_hp_mask (nghq_session *ctx, uint8_t *dest, const uint8_t *hp_key,
                        const uint8_t *sample);

int _transport_recv_stream_data (nghq_session *session, int64_t stream_id,
                                 int fin, uint64_t stream_offset,
                                 const uint8_t *data, size_t datalen);

ssize_t quic_transport_packet_parse (nghq_session *ctx, uint8_t *buf,
                                     size_t len, uint64_t ts) {
  ssize_t rv;
  size_t off = 1, pkt_num_len = 0, i;
  uint8_t hp_mask[5];
  uint64_t pkt_num = 0;

  if (!NGHQ_IS_SHORT_HEADER(buf[0])) {
    return NGHQ_TRANSPORT_ERROR;
  }

  /* Check the connection ID */
  if (memcmp (buf + off, ctx->session_id, ctx->session_id_len) != 0) {
    ERROR("Mismatched session ID!");
    return NGHQ_TRANSPORT_BAD_SESSION_ID;
  }
  nghq_update_timeout (ctx);
  off += ctx->session_id_len;

  /* Get the packet number, after removing potential packet protection */
  _transport_hp_mask (ctx, hp_mask, NULL, NULL);
  buf[0] = buf[0] ^ (hp_mask[0] & 0x1f);
  pkt_num_len = (size_t)((buf[0] & NGHQ_PKT_NUMLEN_MASK) + 1);

  for (i = 0; i < pkt_num_len; ++i) {
    buf[off + i] = buf[off + i] ^ hp_mask[i + 1];
  }
  /* TODO: Figure out where in the sequence this packet number should live */
  pkt_num = get_packet_number (buf[0], buf + off);
  off += pkt_num_len;

  DEBUG ("Received packet with packet number %lu\n", pkt_num);

  /* Remove packet encryption */
  rv = (ssize_t) ctx->callbacks.decrypt_callback (ctx, buf + off, len - off,
                                                  NULL, NULL, 0, NULL, 0,
                                                  buf + off,
                                                  ctx->session_user_data);
  if (rv != NGHQ_OK) {
    return NGHQ_CRYPTO_ERROR;
  }

  /* Parse internals */
  while (off < len) {
    ssize_t _rv = NGHQ_OK;
    //size_t frame_off = off;
    uint64_t frame_type = _get_varlen_int (buf + off, &off, len - off);
    if ((frame_type >= 0x08) && (frame_type <= 0x0f)) {
      _rv = _parse_stream_frame (ctx, (uint8_t) frame_type, buf + off,
                                 len - off);
    } else {
      switch (frame_type) {
        case QUIC_FRAME_PADDING:
          off = len;
          break;
        case QUIC_FRAME_PING:
          /* Already updated timeout */
          _rv = off;
          break;
        case QUIC_FRAME_RESET_STREAM:
          _rv = _parse_reset_stream_frame (ctx, buf + off, len - off);
          break;
        default:
          ERROR ("Received banned or unsupported frame type %X", frame_type);
          return NGHQ_TRANSPORT_FRAME_FORMAT;
      }
    }

    if (_rv < NGHQ_OK) {
      return _rv;
    }
    off += _rv;
  }

  return rv;
}

ssize_t quic_transport_write_quic_header (nghq_session *ctx, uint8_t *buf,
                                          size_t len, uint64_t *pktnum) {
  ssize_t off = 0;
  uint64_t packet_number;
  buf[0] = 0x40; /* Short header, 1 byte packet number */
  if ((ctx->transport_settings.packet_number_length > NGHQ_PKTNUM_LEN_1_BYTE) &&
      (ctx->transport_settings.packet_number_length < NGHQ_PKTNUM_LEN_MAX)) {
    buf[0] += ctx->transport_settings.packet_number_length - 1;
  }
  memcpy(buf + 1, ctx->session_id, ctx->session_id_len);
  off = ctx->session_id_len + 1;
  packet_number = ctx->tx_pkt_num++;
  switch (ctx->transport_settings.packet_number_length) {
    case NGHQ_PKTNUM_LEN_2_BYTE:
    case NGHQ_PKTNUM_LEN_3_BYTE:
    case NGHQ_PKTNUM_LEN_4_BYTE:
      put_packet_number (packet_number,
                         ctx->transport_settings.packet_number_length,
                         buf + off, len);
      off += ctx->transport_settings.packet_number_length;
      break;
    case NGHQ_PKTNUM_LEN_1_BYTE:
    case NGHQ_PKTNUM_LEN_AUTO:
    default:
      buf[off++] = (uint8_t) packet_number;
  }
  *pktnum = packet_number;
  return off;
}

void quic_transport_abandon_packet (nghq_session *ctx, uint8_t *buf,
                                    size_t len, uint64_t pktnum) {
  uint64_t hdr_pkt_num = get_packet_number (buf[0], buf + ctx->session_id_len + 1);
  // TODO: Check all the packet number available
  if ((pktnum & 0x00000000000000FF) != (hdr_pkt_num & 0x00000000000000FF)) {
    ERROR ("Packet number supplied does not match that in the header!\n");
    return;
  }
  if (pktnum == (ctx->tx_pkt_num - 1)) {
    --ctx->tx_pkt_num;
  }
}

ssize_t quic_transport_write_stream (nghq_session *ctx, nghq_stream *stream,
                                     uint8_t *buf_in, size_t len_in,
                                     uint8_t *buf_out, size_t buf_out_len,
                                     int fin, size_t *buf_written) {
  uint64_t stream_frame_type = 0x0aULL; /* Always going to have a length */
  size_t off = 0;
  size_t payload_len = len_in;

  *buf_written = 0;

  if (stream->tx_offset > 0) {
    stream_frame_type = stream_frame_type | 0x04;
  }
  if (fin) {
    stream_frame_type = stream_frame_type | 0x01;
  }

  if (_make_varlen_int (NULL, stream_frame_type) +
      _make_varlen_int (NULL, (uint64_t) stream->stream_id) +
      ((stream->tx_offset)?(_make_varlen_int (NULL, stream->tx_offset)):(0)) +
      _make_varlen_int (NULL, payload_len) > buf_out_len) {
    /* Not enough space to write a stream header */
    ERROR ("Not enough space in packet to write even the stream header!\n");
    return NGHQ_TOO_MUCH_DATA;
  }

  /* Write the stream header */
  off += _make_varlen_int (buf_out + off, stream_frame_type);
  off += _make_varlen_int (buf_out + off, (uint64_t) stream->stream_id);
  if (stream->tx_offset > 0) {
    off += _make_varlen_int (buf_out + off, stream->tx_offset);
  }
  if ((len_in + off + _make_varlen_int (NULL, len_in)) > buf_out_len) {
    if (buf_out_len < off - _make_varlen_int (NULL, buf_out_len - off)) {
      /* Not enough space to create a packet */
      return NGHQ_TOO_MUCH_DATA;
    }
    payload_len = buf_out_len - off - _make_varlen_int (NULL, buf_out_len - off);
    buf_out[0] = buf_out[0] & 0xfe; /* Make sure not to set any FIN bits */
  }
  off += _make_varlen_int (buf_out + off, payload_len);
  assert(off + payload_len <= buf_out_len);

  memcpy (buf_out + off, buf_in, payload_len);

  *buf_written = payload_len;
  stream->tx_offset += payload_len;

  return payload_len + off;
}

ssize_t quic_transport_encrypt (nghq_session *ctx,
                                uint8_t *buf_in, size_t len_in,
                                uint8_t *buf_out, size_t len_out) {
  int rv, i;
  uint8_t hp_mask[5];
  if (ctx->callbacks.encrypt_callback) {
    if (len_out < len_in + ctx->transport_settings.encryption_overhead) {
      return NGHQ_INTERNAL_ERROR;
    }
    rv = ctx->callbacks.encrypt_callback (ctx, buf_in, len_in, NULL, 0, NULL,
                                    ctx->transport_settings.encryption_overhead,
                                    NULL, buf_out, ctx->session_user_data);
    if (rv != NGHQ_OK) return NGHQ_CRYPTO_ERROR;

    _transport_hp_mask (ctx, hp_mask, NULL, NULL);
    buf_in[0] = buf_in[0] ^ (hp_mask[0] & 0x1f);
    for (i = 1; i <= ctx->transport_settings.packet_number_length; i++) {
      buf_in[i + ctx->session_id_len] =
          buf_in[i + ctx->session_id_len] ^ hp_mask[i];
    }
  }
  return len_in + ctx->transport_settings.encryption_overhead;
}

ssize_t quic_transport_write_reset_stream (nghq_session *ctx, uint8_t *buf,
                                           size_t len, nghq_stream* stream,
                                           uint64_t error_code)
{
  ssize_t rv = 0;
  if (stream == NULL) return NGHQ_ERROR;

  /* Make sure there's enough space to write the frame! */
  if (len < (_make_varlen_int(NULL, stream->stream_id) +
      _make_varlen_int(NULL, error_code) +
      _make_varlen_int(NULL, stream->tx_offset))) {
    return NGHQ_ERROR;
  }

  rv += _make_varlen_int (buf, stream->stream_id);
  rv += _make_varlen_int (buf + rv, error_code);
  rv += _make_varlen_int (buf + rv, stream->tx_offset);

  return rv;
}

int64_t quic_transport_open_stream (nghq_session *ctx, nghq_stream_type type) {
  int64_t rv;
  switch (type) {
    case NGHQ_STREAM_CLIENT_BIDI:
    case NGHQ_STREAM_SERVER_BIDI:
      if (ctx->next_stream_id[type] >= ctx->max_open_requests) {
        return NGHQ_TOO_MANY_REQUESTS;
      }
      break;
    case NGHQ_STREAM_CLIENT_UNI:
      if (ctx->next_stream_id[type] >= ctx->max_open_client_uni) {
        return NGHQ_PUSH_LIMIT_REACHED;
      }
      break;
    case NGHQ_STREAM_SERVER_UNI:
      if (ctx->next_stream_id[type] >= ctx->max_open_server_uni) {
        return NGHQ_PUSH_LIMIT_REACHED;
      }
      break;
    default:
      return NGHQ_ERROR;
  }
  rv = (ctx->next_stream_id[type] * 4) + type;
  ++ctx->next_stream_id[type];
  return rv;
}

/* Private */

ssize_t _parse_stream_frame (nghq_session *ctx, uint8_t stream_type,
                             uint8_t *buf, size_t len) {
  ssize_t rv;
  size_t off = 0;
  uint64_t stream_id, offset = 0, length;
  int fin = 0;

  stream_id = _get_varlen_int (buf, &off, len);
  if (stream_type & 0x04) {
    offset = _get_varlen_int (buf + off, &off, len);
  }
  length = len - off;
  if (stream_type & 0x02) {
    length = _get_varlen_int (buf + off, &off, len);
  }
  fin = stream_type & 0x01;

  if (length > len - off) {
    ERROR("QUIC packet incomplete or bad\n");
    return NGHQ_TRANSPORT_FRAME_FORMAT;
  }

  rv = (ssize_t) _transport_recv_stream_data (ctx, (int64_t) stream_id, fin,
                                              offset, buf+off, length);
  if (rv < 0) return rv;

  return length + off;
}

size_t _write_quic_header (nghq_session *ctx, uint8_t *buf, size_t len) {
  size_t off = 0;
  /* TODO: Make it possible for packet numbers to be > 1 byte */
  buf[0] = 0x40; /* Short header, 1 byte packet number */
  memcpy(buf + 1, ctx->session_id, ctx->session_id_len);
  off = ctx->session_id_len + 1;
  buf[off++] = (uint8_t) ctx->rx_pkt_num++;
  return off;
}

/*
 * A copy from nghq_transport_recv_stream_data in tcp2_callbacks with a slightly
 * different interface, before the divorce from ngtcp2.
 */
int _transport_recv_stream_data (nghq_session *session, int64_t stream_id,
                                 int fin, uint64_t stream_offset,
                                 const uint8_t *data, size_t datalen) {
  DEBUG ("_transport_recv_stream_data(%p, %lu, %x, data(%lu))\n",
         (void *) session, stream_id, fin, datalen);
  nghq_stream* stream = nghq_stream_id_map_find(session->transfers, stream_id);
  nghq_stream_type stype = stream_id % 4;
  size_t data_offset = 0;
  int rv;

  if (stream == NULL) {
    /* New stream time! */
    DEBUG("Seen start of new stream %lu\n", stream_id);
    stream = nghq_stream_new(stream_id);
    if (stream == NULL) {
      return NGHQ_OUT_OF_MEMORY;
    }
    if (stream_id < session->next_stream_id[stype]) {
      ERROR("New stream ID (%u) is less than the expected new stream ID (%u)",
            stream_id,
            ((session->next_stream_id[stype] * 4) + stype));
      return NGHQ_TRANSPORT_BAD_STREAM_ID;
    } else {
      session->next_stream_id[stype] = (stream_id - stype) / 4;
    }
    nghq_stream_id_map_add(session->transfers, stream_id, stream);
    if (CLIENT_REQUEST_STREAM(stream_id)) {
      if ((stream_id == 0) && (session->mode == NGHQ_MODE_MULTICAST)) {
        /*
         * Don't feed the magic packet into nghq_recv_stream_data as it will
         * upset it. Just return 0 so that stream 0 is at least open, ready
         * to send our first PUSH_PROMISE
         */
        return 0;
      }
    }
  }

  if (SERVER_PUSH_STREAM(stream_id) && stream_offset==0 &&
        (_get_varlen_int(data, &data_offset, datalen) == 0x1)) {
    /* Find the server push stream! */
    nghq_stream* push_stream;
    uint64_t push_id = _get_varlen_int(data + data_offset, &data_offset, datalen);
    if (data_offset > datalen) {
      ERROR("Not enough data for push ID in stream data for stream %lu\n",
            stream_id);
      return NGHQ_ERROR;
    }
    push_stream = nghq_stream_id_map_find(session->promises, push_id);
    if (push_stream == NULL) {
      ERROR("Received new server push stream %lu, but Push ID %lu has not "
            "been previously promised, or has already been started!\n",
            stream_id, push_id);
      return NGHQ_HTTP_BAD_PUSH;
    }

    /* copy over push information to stream */
    stream->push_id = push_id;
    stream->user_data = push_stream->user_data;

    nghq_stream_id_map_remove(session->promises, push_id);
    nghq_stream_ended(session, push_stream);

    DEBUG("Server push stream %lu starts push promise %lu\n",
          stream_id, push_id);
  }

  if (stream->stream_id != stream_id) {
    ERROR ("Stream IDs do not match! (%ld != %ld)\n", stream->stream_id,
           stream_id);
    return NGHQ_INTERNAL_ERROR;
  }

  rv = nghq_recv_stream_data(session, stream, data, datalen, stream_offset,
                             fin);

  if (rv == NGHQ_NOT_INTERESTED) {
    /* Client has indicated it doesn't care about this stream anymore, stop */
    nghq_stream_cancel (session, stream, 0);
  }

  return rv;
}

ssize_t _parse_reset_stream_frame (nghq_session *ctx, uint8_t *buf, size_t len){
  size_t off = 0;
  uint64_t stream_id, app_error_code, final_size;
  nghq_stream *stream;

  stream_id = _get_varlen_int (buf, &off, len);
  app_error_code = _get_varlen_int (buf, &off, len);
  final_size = _get_varlen_int (buf, &off, len);

  DEBUG ("Received RESET_STREAM for stream ID %lu, error code %lu and final "
         "size of %lu\n", stream_id, app_error_code, final_size);

  stream = nghq_stream_id_map_find (ctx->transfers, stream_id);
  if (stream == NULL) {
    ERROR ("Received reset stream for %lu, but couldn't find it in the map\n",
           stream_id);
    return NGHQ_REQUEST_CLOSED;
  }
  nghq_stream_ended (ctx, stream);
  return len;
}

int _transport_hp_mask (nghq_session *ctx, uint8_t *dest, const uint8_t *hp_key,
                        const uint8_t *sample)
{
  /* TODO? */
  memcpy (dest, _hp_mask, 5);
  return 0;
}

