/*
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <atomic.h>
#include <misc/byteorder.h>
#include <misc/util.h>

#include <bluetooth/hci.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>

#if defined(CONFIG_TINYCRYPT_AES)
#include <tinycrypt/aes.h>
#include <tinycrypt/utils.h>
#endif

#include "hci_core.h"
#include "conn_internal.h"
#include "smp.h"

/* nble internal APIs */
#include "gap_internal.h"

#ifdef CONFIG_SYSTEM_EVENTS
#include "infra/system_events.h"
#endif

/* #define BT_GATT_DEBUG 1 */

extern void on_nble_curie_log(char *fmt, ...);
extern void __assert_fail(void);
#ifdef BT_GATT_DEBUG
#define BT_DBG(fmt, ...) on_nble_curie_log(fmt, ##__VA_ARGS__)
#define BT_ERR(fmt, ...) on_nble_curie_log(fmt, ##__VA_ARGS__)
#define BT_WARN(fmt, ...) on_nble_curie_log(fmt, ##__VA_ARGS__)
#define BT_INFO(fmt, ...) on_nble_curie_log(fmt, ##__VA_ARGS__)
#define BT_ASSERT(cond) ((cond) ? (void)0 : __assert_fail())
#else
#define BT_DBG(fmt, ...) do {} while (0)
#define BT_ERR(fmt, ...) on_nble_curie_log(fmt, ##__VA_ARGS__)
#define BT_WARN(fmt, ...) on_nble_curie_log(fmt, ##__VA_ARGS__)
#define BT_INFO(fmt, ...) on_nble_curie_log(fmt, ##__VA_ARGS__)
#define BT_ASSERT(cond) ((cond) ? (void)0 : __assert_fail())
#endif

#define BT_SMP_AUTH_MASK	0x07
#define BT_SMP_AUTH_MASK_SC	0x0f

enum pairing_method {
	JUST_WORKS,		/* JustWorks pairing */
	PASSKEY_INPUT,		/* Passkey Entry input */
	PASSKEY_DISPLAY,	/* Passkey Entry display */
	PASSKEY_CONFIRM,	/* Passkey confirm */
	PASSKEY_ROLE,		/* Passkey Entry depends on role */
};

enum {
	SMP_FLAG_CFM_DELAYED,	/* if confirm should be send when TK is valid */
	SMP_FLAG_ENC_PENDING,	/* if waiting for an encryption change event */
	SMP_FLAG_KEYS_DISTR,	/* if keys distribution phase is in progress */
	SMP_FLAG_PAIRING,	/* if pairing is in progress */
	SMP_FLAG_TIMEOUT,	/* if SMP timeout occurred */
	SMP_FLAG_SC,		/* if LE Secure Connections is used */
	SMP_FLAG_PKEY_SEND,	/* if should send Public Key when available */
	SMP_FLAG_DHKEY_PENDING,	/* if waiting for local DHKey */
	SMP_FLAG_DHKEY_SEND,	/* if should generate and send DHKey Check */
	SMP_FLAG_USER,		/* if waiting for user input */
	SMP_FLAG_BOND,		/* if bonding */
};

/* SMP channel specific context */
struct bt_smp {
	/* The channel this context is associated with (nble conn object)*/
	struct bt_conn		*conn;

#if NOT_APPLICABLE_NBLE
	/* SMP Timeout fiber handle */
	void			*timeout;

	/* Commands that remote is allowed to send */
	atomic_t		allowed_cmds;
#endif
	/* Flags for SMP state machine */
	atomic_t		flags;
#if NOT_USED_FOR_NOW
	/* Type of method used for pairing */
	uint8_t			method;
#endif
};

static struct bt_smp bt_smp_pool[CONFIG_BLUETOOTH_MAX_CONN];
static bool sc_supported;

/**
 * Compile time IO capabilities and OOB support settings for nble.
 *
 * This compile options must match the application registered callbacks
 * (bt_conn_auth_cb_register)
 */
#if defined(CONFIG_BLUETOOTH_IO_KEYBOARD_DISPLAY)
#define NBLE_SMP_IO_CAPS BT_SMP_IO_KEYBOARD_DISPLAY
#elif defined(CONFIG_BLUETOOTH_IO_DISPLAY_YESNO)
#define NBLE_SMP_IO_CAPS BT_SMP_IO_DISPLAY_YESNO
#elif defined(CONFIG_BLUETOOTH_IO_KEYBOARD)
#define NBLE_SMP_IO_CAPS BT_SMP_IO_KEYBOARD_ONLY
#elif defined(CONFIG_BLUETOOTH_IO_DISPLAY)
#define NBLE_SMP_IO_CAPS BT_SMP_IO_DISPLAY_ONLY
#else
#define NBLE_SMP_IO_CAPS BT_SMP_IO_NO_INPUT_OUTPUT
#endif

#if (defined(CONFIG_BLUETOOTH_IO_KEYBOARD_DISPLAY) || \
		defined(CONFIG_BLUETOOTH_IO_DISPLAY_YESNO) || \
		defined(CONFIG_BLUETOOTH_IO_KEYBOARD) || \
		defined(CONFIG_BLUETOOTH_IO_DISPLAY))
#define NBLE_SMP_AUTH_OPTIONS BT_SMP_AUTH_BONDING | BT_SMP_AUTH_MITM
#else
#define NBLE_SMP_AUTH_OPTIONS BT_SMP_AUTH_BONDING
#endif
/* TODO: BT_SMP_AUTH_SC */

#if NOT_USED_FOR_NOW
static uint8_t get_io_capa(void)
{
	if (!bt_auth) {
		return BT_SMP_IO_NO_INPUT_OUTPUT;
	}

	/* Passkey Confirmation is valid only for LE SC */
	if (bt_auth->passkey_display && bt_auth->passkey_entry &&
	    (bt_auth->passkey_confirm || !sc_supported)) {
		return BT_SMP_IO_KEYBOARD_DISPLAY;
	}

	/* DisplayYesNo is useful only for LE SC */
	if (sc_supported && bt_auth->passkey_display &&
	    bt_auth->passkey_confirm) {
		return BT_SMP_IO_DISPLAY_YESNO;
	}

	if (bt_auth->passkey_entry) {
		return BT_SMP_IO_KEYBOARD_ONLY;
	}

	if (bt_auth->passkey_display) {
		return BT_SMP_IO_DISPLAY_ONLY;
	}

	return BT_SMP_IO_NO_INPUT_OUTPUT;
}

static uint8_t get_pair_method(struct bt_smp *smp, uint8_t remote_io)
{
	struct bt_smp_pairing *req, *rsp;

	if (remote_io > BT_SMP_IO_KEYBOARD_DISPLAY)
		return JUST_WORKS;

	req = (struct bt_smp_pairing *)&smp->preq[1];
	rsp = (struct bt_smp_pairing *)&smp->prsp[1];

	/* if none side requires MITM use JustWorks */
	if (!((req->auth_req | rsp->auth_req) & BT_SMP_AUTH_MITM)) {
		return JUST_WORKS;
	}

	return gen_method_sc[remote_io][get_io_capa()];
}
#endif

static void smp_reset(struct bt_smp *smp)
{
	struct bt_conn *conn = smp->conn;

#if NOT_APPLICABLE_NBLE
	if (smp->timeout) {
		fiber_fiber_delayed_start_cancel(smp->timeout);
		smp->timeout = NULL;

		stack_analyze("smp timeout stack", smp->stack,
			      sizeof(smp->stack));
	}

	smp->method = JUST_WORKS;
	atomic_set(&smp->allowed_cmds, 0);
#endif
	smp->flags = 0;

	if (conn->required_sec_level != conn->sec_level) {
		/* TODO report error */
		/* reset required security level in case of error */
		conn->required_sec_level = conn->sec_level;
	}

#if NOT_APPLICABLE_NBLE
#if defined(CONFIG_BLUETOOTH_CENTRAL)
	if (conn->role == BT_HCI_ROLE_MASTER) {
		atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_SECURITY_REQUEST);
		return;
	}
#endif /* CONFIG_BLUETOOTH_CENTRAL */

#if defined(CONFIG_BLUETOOTH_PERIPHERAL)
	atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_REQ);
#endif /* CONFIG_BLUETOOTH_PERIPHERAL */
#endif
}

static void nble_security_reply(struct bt_conn *conn,
			       struct nble_gap_sm_passkey *par)
{
	struct nble_gap_sm_key_reply_req_params params = {
			.conn = conn,
			.conn_handle = conn->handle,
			.params = *par,
	};

	nble_gap_sm_passkey_reply_req(&params);
}

static int smp_error(struct bt_smp *smp, uint8_t reason)
{
	struct nble_gap_sm_passkey params = {
			/* used to cancel an ongoing pairing */
			.type = NBLE_GAP_SM_REJECT,
			.reason = reason,
	};

	nble_security_reply(smp->conn, &params);

	/* nble will return a status event in any case */
#if NOT_APPLICABLE_NBLE
	/* reset context */
	smp_reset(smp);
#endif

#if NOT_APPLICABLE_NBLE
	buf = smp_create_pdu(smp->chan.conn, BT_SMP_CMD_PAIRING_FAIL,
			     sizeof(*rsp));
	if (!buf) {
		return -ENOBUFS;
	}

	rsp = net_buf_add(buf, sizeof(*rsp));
	rsp->reason = reason;

	/* SMP timer is not restarted for PairingFailed so don't use smp_send */
	bt_l2cap_send(smp->chan.conn, BT_L2CAP_CID_SMP, buf);
#endif
	return 0;
}

static void legacy_passkey_entry(struct bt_smp *smp, unsigned int passkey)
{
	struct nble_gap_sm_passkey params = {
			.type = NBLE_GAP_SM_PK_PASSKEY,
			.passkey = sys_cpu_to_le32(passkey),
	};

#if 0
	passkey = sys_cpu_to_le32(passkey);
	memcpy(smp->tk, &passkey, sizeof(passkey));

	if (!atomic_test_and_clear_bit(&smp->flags, SMP_FLAG_CFM_DELAYED)) {
		smp_error(smp, BT_SMP_ERR_PASSKEY_ENTRY_FAILED);
		return;
	}
#endif

	nble_security_reply(smp->conn, &params);

#if NOT_APPLICABLE_NBLE
	/* if confirm failed ie. due to invalid passkey, cancel pairing */
	if (legacy_pairing_confirm(smp)) {
		smp_error(smp, BT_SMP_ERR_PASSKEY_ENTRY_FAILED);
		return;
	}

#if defined(CONFIG_BLUETOOTH_CENTRAL)
	if (smp->chan.conn->role == BT_HCI_ROLE_MASTER) {
		atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_CONFIRM);
		return;
	}
#endif /* CONFIG_BLUETOOTH_CENTRAL */

#if defined(CONFIG_BLUETOOTH_PERIPHERAL)
	atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_RANDOM);
#endif /* CONFIG_BLUETOOTH_PERIPHERAL */
#endif
}

static int smp_init(struct bt_smp *smp)
{
	/* Initialize SMP context without clearing L2CAP channel context */
	memset((uint8_t *)smp + sizeof(smp->conn), 0,
	       sizeof(*smp) - sizeof(smp->conn));

#if NOT_APPLICABLE_TO_NBLE
	/* Generate local random number */
	if (bt_rand(smp->prnd, 16)) {
		return BT_SMP_ERR_UNSPECIFIED;
	}

	BT_DBG("prnd %s", h(smp->prnd, 16));

	atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_FAIL);
#endif

	return 0;
}

#if NOT_USED_FOR_NOW
static uint8_t get_auth(uint8_t auth)
{
	if (sc_supported) {
		auth &= BT_SMP_AUTH_MASK_SC;
	} else {
		auth &= BT_SMP_AUTH_MASK;
	}

	if (get_io_capa() == BT_SMP_IO_NO_INPUT_OUTPUT) {
		auth &= ~(BT_SMP_AUTH_MITM);
	} else {
		auth |= BT_SMP_AUTH_MITM;
	}

	return auth;
}
#endif

static bool sec_level_reachable(struct bt_conn *conn)
{
	switch (conn->required_sec_level) {
	case BT_SECURITY_LOW:
	case BT_SECURITY_MEDIUM:
		return true;
	case BT_SECURITY_HIGH:
		return NBLE_SMP_IO_CAPS != BT_SMP_IO_NO_INPUT_OUTPUT;
	case BT_SECURITY_FIPS:
		return NBLE_SMP_IO_CAPS != BT_SMP_IO_NO_INPUT_OUTPUT &&
		       sc_supported;
	default:
		return false;
	}
}

static struct bt_smp *smp_chan_get(struct bt_conn *conn)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(bt_smp_pool); i++) {
		struct bt_smp *smp = &bt_smp_pool[i];

		if (smp->conn == conn) {
			return smp;
		}
	}

	return NULL;
}

#if defined(CONFIG_BLUETOOTH_PERIPHERAL) || defined(CONFIG_BLUETOOTH_CENTRAL)
static void nble_start_security(struct bt_conn *conn)
{
	struct nble_gap_sm_security_params params = {
			.conn = conn,
			.conn_handle = conn->handle,
			.params = {
				.auth_level = NBLE_SMP_AUTH_OPTIONS,
			},
	};

	nble_gap_sm_security_req(&params);
}
#endif

#if defined(CONFIG_BLUETOOTH_PERIPHERAL)
int bt_smp_send_security_req(struct bt_conn *conn)
{
	struct bt_smp *smp;

	smp = smp_chan_get(conn);
	if (!smp) {
		return -ENOTCONN;
	}

	/* SMP Timeout */
	if (atomic_test_bit(&smp->flags, SMP_FLAG_TIMEOUT)) {
		return -EIO;
	}

	/* pairing is in progress */
	if (atomic_test_bit(&smp->flags, SMP_FLAG_PAIRING)) {
		return -EBUSY;
	}

	/* early verify if required sec level if reachable */
	if (!sec_level_reachable(conn)) {
		return -EINVAL;
	}

	nble_start_security(conn);

#if NOT_APPLICABLE_NBLE
	/* early verify if required sec level if reachable */
	if (!sec_level_reachable(conn)) {
		return -EINVAL;
	}

	req_buf = smp_create_pdu(conn, BT_SMP_CMD_SECURITY_REQUEST,
				 sizeof(*req));
	if (!req_buf) {
		return -ENOBUFS;
	}

	req = net_buf_add(req_buf, sizeof(*req));
	req->auth_req = get_auth(BT_SMP_AUTH_BONDING | BT_SMP_AUTH_SC);

	/* SMP timer is not restarted for SecRequest so don't use smp_send */
	bt_l2cap_send(conn, BT_L2CAP_CID_SMP, req_buf);

	atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_FAIL);
#endif

	return 0;
}
#endif /* CONFIG_BLUETOOTH_PERIPHERAL */

#if defined(CONFIG_BLUETOOTH_CENTRAL)
int bt_smp_send_pairing_req(struct bt_conn *conn)
{
	struct bt_smp *smp;

	/* BT_DBG(""); */

	smp = smp_chan_get(conn);
	if (!smp) {
		return -ENOTCONN;
	}

	/* SMP Timeout */
	if (atomic_test_bit(&smp->flags, SMP_FLAG_TIMEOUT)) {
		return -EIO;
	}

	/* pairing is in progress */
	if (atomic_test_bit(&smp->flags, SMP_FLAG_PAIRING)) {
		return -EBUSY;
	}

	/* early verify if required sec level if reachable */
	if (!sec_level_reachable(conn)) {
		return -EINVAL;
	}

	if (smp_init(smp)) {
		return -ENOBUFS;
	}

#ifdef NOT_APPLICABLE_NBLE
	req_buf = smp_create_pdu(conn, BT_SMP_CMD_PAIRING_REQ, sizeof(*req));
	if (!req_buf) {
		return -ENOBUFS;
	}

	req = net_buf_add(req_buf, sizeof(*req));

	req->auth_req = get_auth(BT_SMP_AUTH_BONDING | BT_SMP_AUTH_SC);
	req->io_capability = get_io_capa();
	req->oob_flag = BT_SMP_OOB_NOT_PRESENT;
	req->max_key_size = BT_SMP_MAX_ENC_KEY_SIZE;
	req->init_key_dist = SEND_KEYS;
	req->resp_key_dist = RECV_KEYS;

	smp->local_dist = SEND_KEYS;
	smp->remote_dist = RECV_KEYS;

	/* Store req for later use */
	smp->preq[0] = BT_SMP_CMD_PAIRING_REQ;
	memcpy(smp->preq + 1, req, sizeof(*req));

	smp_send(smp, req_buf);
	atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_RSP);
#endif

	nble_start_security(conn);

	atomic_set_bit(&smp->flags, SMP_FLAG_PAIRING);
	return 0;
}
#endif /* CONFIG_BLUETOOTH_CENTRAL */

#if NOT_USED_FOR_NOW
static uint8_t display_passkey(struct bt_smp *smp)
{
	if (bt_rand(&smp->passkey, sizeof(smp->passkey))) {
		return BT_SMP_ERR_UNSPECIFIED;
	}

	smp->passkey %= 1000000;
	smp->passkey_round = 0;

	bt_auth->passkey_display(smp->chan.conn, smp->passkey);
	smp->passkey = sys_cpu_to_le32(smp->passkey);

	return 0;
}
#endif

#if NOT_USED_FOR_NOW
#if defined(CONFIG_BLUETOOTH_PERIPHERAL)
static uint8_t smp_public_key_slave(struct bt_smp *smp)
{
	uint8_t err;

	err = sc_send_public_key(smp);
	if (err) {
		return err;
	}

	switch (smp->method) {
	case PASSKEY_CONFIRM:
	case JUST_WORKS:
		atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_RANDOM);

		err = smp_send_pairing_confirm(smp);
		if (err) {
			return err;
		}
		break;
	case PASSKEY_DISPLAY:
		err = display_passkey(smp);
		if (err) {
			return err;
		}

		atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_CONFIRM);
		break;
	case PASSKEY_INPUT:
		atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_CONFIRM);
		atomic_set_bit(&smp->flags, SMP_FLAG_USER);
		bt_auth->passkey_entry(smp->chan.conn);
		break;
	default:
		return BT_SMP_ERR_UNSPECIFIED;
	}

	return generate_dhkey(smp);
}
#endif /* CONFIG_BLUETOOTH_PERIPHERAL */

static uint8_t smp_public_key(struct bt_smp *smp, struct net_buf *buf)
{
	struct bt_smp_public_key *req = (void *)buf->data;
	uint8_t err;

	BT_DBG("");

	memcpy(smp->pkey, req->x, 32);
	memcpy(&smp->pkey[32], req->y, 32);

#if defined(CONFIG_BLUETOOTH_CENTRAL)
	if (smp->chan.conn->role == BT_HCI_ROLE_MASTER) {
		switch (smp->method) {
		case PASSKEY_CONFIRM:
		case JUST_WORKS:
			atomic_set_bit(&smp->allowed_cmds,
				       BT_SMP_CMD_PAIRING_CONFIRM);
			break;
		case PASSKEY_DISPLAY:
			err = display_passkey(smp);
			if (err) {
				return err;
			}

			atomic_set_bit(&smp->allowed_cmds,
				       BT_SMP_CMD_PAIRING_CONFIRM);

			err = smp_send_pairing_confirm(smp);
			if (err) {
				return err;
			}
			break;
		case PASSKEY_INPUT:
			atomic_set_bit(&smp->flags, SMP_FLAG_USER);
			bt_auth->passkey_entry(smp->chan.conn);
			break;
		default:
			return BT_SMP_ERR_UNSPECIFIED;
		}

		return generate_dhkey(smp);
	}
#endif /* CONFIG_BLUETOOTH_CENTRAL */
#if defined(CONFIG_BLUETOOTH_PERIPHERAL)
	if (!sc_local_pkey_valid) {
		atomic_set_bit(&smp->flags, SMP_FLAG_PKEY_SEND);
		return 0;
	}

	err = smp_public_key_slave(smp);
	if (err) {
		return err;
	}
#endif /* CONFIG_BLUETOOTH_PERIPHERAL */

	return 0;
}
#endif /* NOT_USED_FOR_NOW */

void on_nble_gap_sm_bond_info_rsp(const struct nble_gap_sm_bond_info_rsp *rsp,
		const bt_addr_le_t *peer_addr, uint16_t len)
{
	ble_bond_info_cb_t cb = rsp->cb;

	if (cb) {
		cb(&rsp->info, peer_addr, len, rsp->user_data);
	}
}

void on_nble_gap_sm_passkey_req_evt(const struct nble_gap_sm_passkey_req_evt * p_evt)
{
	struct bt_conn *conn = bt_conn_lookup_handle(p_evt->conn_handle);

	if (conn) {
		struct bt_smp *smp = smp_chan_get(conn);

		bt_conn_unref(conn);

		atomic_set_bit(&smp->flags, SMP_FLAG_USER);

		if (p_evt->key_type == NBLE_GAP_SM_PK_PASSKEY)
			bt_auth->passkey_entry(conn);
	}
}

void on_nble_gap_sm_passkey_display_evt(
		const struct nble_gap_sm_passkey_disp_evt *p_evt)
{
#if defined(CONFIG_BLUETOOTH_IO_DISPLAY_YESNO) || \
		defined(CONFIG_BLUETOOTH_IO_KEYBOARD_DISPLAY) || \
			defined(CONFIG_BLUETOOTH_IO_DISPLAY)
	struct bt_conn *conn = bt_conn_lookup_handle(p_evt->conn_handle);

	if (conn) {
		struct bt_smp *smp = smp_chan_get(conn);

		bt_conn_unref(conn);

#if defined(CONFIG_BLUETOOTH_IO_DISPLAY_YESNO)
		bt_auth->passkey_confirm(smp->conn, p_evt->passkey);
#else
		bt_auth->passkey_display(smp->conn, p_evt->passkey);
#endif
	}
#endif
}

void on_nble_gap_sm_status_evt(const struct nble_gap_sm_status_evt *evt)
{
	struct bt_conn *conn;

	conn = bt_conn_lookup_handle(evt->conn_handle);
	if (conn) {
		bt_conn_unref(conn);

		BT_INFO("nble sm evt_type:%d, status:0x%x", evt->evt_type,
			evt->status);

		switch (evt->evt_type) {
		case NBLE_GAP_SM_EVT_START_PAIRING: {
			struct bt_smp *smp = smp_chan_get(conn);

			if (smp) {
				/* SMP pairing request Master -> Slave, maybe
				 * this should go into bt_smp_security_req() */
				if (conn->role == BT_HCI_ROLE_SLAVE) {
					smp_init(smp);
				}
				atomic_set_bit(&smp->flags, SMP_FLAG_PAIRING);

				if (conn->role == BT_HCI_ROLE_MASTER) {
					nble_start_security(conn);
				}
				/* TODO: add application callback for start of
				 * pairing procedure */
			}
		}
			break;
		case NBLE_GAP_SM_EVT_BONDING_COMPLETE: {
			struct bt_smp *smp = smp_chan_get(conn);

			if (smp) {
				if (!evt->status) {
					/* TODO: add application callback for
					 * completion of pairing procedure */
#ifdef CONFIG_SYSTEM_EVENTS
					system_event_push_ble_pairing(true);
#endif
				} else {
					if (bt_auth)
						bt_auth->cancel(conn);
				}
				/* Pairing completed. */
				smp_reset(smp);
			}
		}
			break;
		case NBLE_GAP_SM_EVT_LINK_ENCRYPTED:
			conn->sec_level = evt->enc_link_sec.sec_level;
			/* TODO:
			conn->keys->enc_size = p_evt->enc_link_sec.enc_size */
			conn->encrypt = 1;
			/* fall through on purpose, only above event reports
			 * security level. */
		case NBLE_GAP_SM_EVT_LINK_SECURITY_CHANGE:
			bt_conn_security_changed(conn);
			break;
		default:
			break;
		}
	}
}

#if NOT_USED_FOR_NOW
static const struct {
	uint8_t  (*func)(struct bt_smp *smp, struct net_buf *buf);
	uint8_t  expect_len;
} handlers[] = {
	{ }, /* No op-code defined for 0x00 */
	{ smp_pairing_req,         sizeof(struct bt_smp_pairing) },
	{ smp_pairing_rsp,         sizeof(struct bt_smp_pairing) },
	{ smp_pairing_confirm,     sizeof(struct bt_smp_pairing_confirm) },
	{ smp_pairing_random,      sizeof(struct bt_smp_pairing_random) },
	{ smp_pairing_failed,      sizeof(struct bt_smp_pairing_fail) },
	{ smp_encrypt_info,        sizeof(struct bt_smp_encrypt_info) },
	{ smp_master_ident,        sizeof(struct bt_smp_master_ident) },
	{ smp_ident_info,          sizeof(struct bt_smp_ident_info) },
	{ smp_ident_addr_info,     sizeof(struct bt_smp_ident_addr_info) },
	{ smp_signing_info,        sizeof(struct bt_smp_signing_info) },
	{ smp_security_request,    sizeof(struct bt_smp_security_request) },
	{ smp_public_key,          sizeof(struct bt_smp_public_key) },
	{ smp_dhkey_check,         sizeof(struct bt_smp_dhkey_check) },
};

static void bt_smp_recv(struct bt_l2cap_chan *chan, struct net_buf *buf)
{
	struct bt_smp *smp = CONTAINER_OF(chan, struct bt_smp, chan);
	struct bt_smp_hdr *hdr = (void *)buf->data;
	uint8_t err;

	if (buf->len < sizeof(*hdr)) {
		BT_ERR("Too small SMP PDU received");
		return;
	}

	BT_DBG("Received SMP code 0x%02x len %u", hdr->code, buf->len);

	net_buf_pull(buf, sizeof(*hdr));

	/*
	 * If SMP timeout occurred "no further SMP commands shall be sent over
	 * the L2CAP Security Manager Channel. A new SM procedure shall only be
	 * performed when a new physical link has been established."
	 */
	if (atomic_test_bit(&smp->flags, SMP_FLAG_TIMEOUT)) {
		BT_WARN("SMP command (code 0x%02x) received after timeout",
			hdr->code);
		return;
	}

	if (hdr->code >= ARRAY_SIZE(handlers) || !handlers[hdr->code].func) {
		BT_WARN("Unhandled SMP code 0x%02x", hdr->code);
		err = BT_SMP_ERR_CMD_NOTSUPP;
	} else {
		if (!atomic_test_and_clear_bit(&smp->allowed_cmds, hdr->code)) {
			BT_WARN("Unexpected SMP code 0x%02x", hdr->code);
			return;
		}

		if (buf->len != handlers[hdr->code].expect_len) {
			BT_ERR("Invalid len %u for code 0x%02x", buf->len,
			       hdr->code);
			err = BT_SMP_ERR_INVALID_PARAMS;
		} else {
			err = handlers[hdr->code].func(smp, buf);
		}
	}

	if (err) {
		smp_error(smp, err);
	}
}
#endif /* NOT_USED_FOR_NOW */

void bt_smp_connected(struct bt_conn *conn) {

	struct bt_smp *smp = NULL;
	int i;

	/* bt_smp_accept */
	for (i = 0; i < ARRAY_SIZE(bt_smp_pool); i++) {
		smp = &bt_smp_pool[i];

		if (!smp->conn) {
			break;
		}
	}
	BT_ASSERT(i < ARRAY_SIZE(bt_smp_pool));
	smp->conn = conn;

	smp_reset(smp);
}

void bt_smp_disconnected(struct bt_conn *conn) {
	struct bt_smp *smp = smp_chan_get(conn);

	if (smp) {
		memset(smp, 0, sizeof(*smp));
	}
}

static inline int smp_self_test(void)
{
	return 0;
}

int bt_smp_auth_passkey_entry(struct bt_conn *conn, unsigned int passkey)
{
	struct bt_smp *smp;

	smp = smp_chan_get(conn);
	if (!smp) {
		return -EINVAL;
	}

	if (!atomic_test_and_clear_bit(&smp->flags, SMP_FLAG_USER)) {
		return -EINVAL;
	}

#if !defined(CONFIG_BLUETOOTH_SMP_SC_ONLY)
	if (!atomic_test_bit(&smp->flags, SMP_FLAG_SC)) {
		legacy_passkey_entry(smp, passkey);
		return 0;
	}
#endif /* !CONFIG_BLUETOOTH_SMP_SC_ONLY */

#if NOT_APPLICABLE_NBLE
	smp->passkey = sys_cpu_to_le32(passkey);

#if defined(CONFIG_BLUETOOTH_CENTRAL)
	if (smp->chan.conn->role == BT_HCI_ROLE_MASTER) {
		if (smp_send_pairing_confirm(smp)) {
			smp_error(smp, BT_SMP_ERR_PASSKEY_ENTRY_FAILED);
			return 0;
		}
		atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_CONFIRM);
		return 0;
	}
#endif /* CONFIG_BLUETOOTH_CENTRAL */
#if defined(CONFIG_BLUETOOTH_PERIPHERAL)
	if (atomic_test_bit(&smp->flags, SMP_FLAG_CFM_DELAYED)) {
		if (smp_send_pairing_confirm(smp)) {
			smp_error(smp, BT_SMP_ERR_PASSKEY_ENTRY_FAILED);
			return 0;
		}
		atomic_set_bit(&smp->allowed_cmds, BT_SMP_CMD_PAIRING_RANDOM);
	}
#endif /* CONFIG_BLUETOOTH_PERIPHERAL */
#endif

	return 0;
}

int bt_smp_auth_passkey_confirm(struct bt_conn *conn, bool match)
{
	struct bt_smp *smp;

	smp = smp_chan_get(conn);
	if (!smp) {
		return -EINVAL;
	}

	if (!atomic_test_and_clear_bit(&smp->flags, SMP_FLAG_USER)) {
		return -EINVAL;
	}

	/* if passkey doen't match abort pairing */
	if (!match) {
		return smp_error(smp, BT_SMP_ERR_CONFIRM_FAILED);
	}

#if NOT_APPLICABLE_TO_NBLE
	/* wait for DHKey being generated */
	if (atomic_test_bit(&smp->flags, SMP_FLAG_DHKEY_PENDING)) {
		atomic_set_bit(&smp->flags, SMP_FLAG_DHKEY_SEND);
		return 0;
	}

	if (atomic_test_bit(&smp->flags, SMP_FLAG_DHKEY_SEND)) {
		uint8_t err;
#if defined(CONFIG_BLUETOOTH_CENTRAL)
		if (smp->chan.conn->role == BT_HCI_ROLE_MASTER) {
			err = compute_and_send_master_dhcheck(smp);
			if (err) {
				smp_error(smp, err);
			}
			return 0;
		}
#endif /* CONFIG_BLUETOOTH_CENTRAL */
#if defined(CONFIG_BLUETOOTH_PERIPHERAL)
		err = compute_and_check_and_send_slave_dhcheck(smp);
		if (err) {
			smp_error(smp, err);
		}
#endif /* CONFIG_BLUETOOTH_PERIPHERAL */
	}

#endif
	return 0;
}

int bt_smp_auth_cancel(struct bt_conn *conn)
{
	struct bt_smp *smp;

	smp = smp_chan_get(conn);
	if (!smp) {
		return -EINVAL;
	}

	return smp_error(smp, BT_SMP_ERR_PASSKEY_ENTRY_FAILED);
}

#if NOT_USED
static int bt_smp_accept(struct bt_conn *conn, struct bt_l2cap_chan **chan)
{
	int i;
	static struct bt_l2cap_chan_ops ops = {
		.connected = bt_smp_connected,
		.disconnected = bt_smp_disconnected,
		.encrypt_change = bt_smp_encrypt_change,
		.recv = bt_smp_recv,
	};

	BT_DBG("conn %p handle %u", conn, conn->handle);

	for (i = 0; i < ARRAY_SIZE(bt_smp_pool); i++) {
		struct bt_smp *smp = &bt_smp_pool[i];

		if (smp->chan.conn) {
			continue;
		}

		smp->chan.ops = &ops;

		*chan = &smp->chan;

		return 0;
	}

	BT_ERR("No available SMP context for conn %p", conn);

	return -ENOMEM;
}
#endif /* NOT_USED */

/* TODO check tinycrypt define when ECC is added */
#if defined(CONFIG_TINYCRYPT_ECC_DH)
static bool le_sc_supported(void)
{
	/* TODO */
	return false;
}
#else
static bool le_sc_supported(void)
{
	/*
	 * If controller based ECC is to be used it must support
	 * "LE Read Local P-256 Public Key" and "LE Generate DH Key" commands.
	 * Otherwise LE SC are not supported.
	 */
	return false; /* currently nordic does not support security level 4 */
}
#endif

int bt_smp_init(void)
{
	struct nble_gap_sm_config_params params = {
			.options = NBLE_SMP_AUTH_OPTIONS,
			.io_caps = NBLE_SMP_IO_CAPS,
			.key_size = BT_SMP_MAX_ENC_KEY_SIZE,
			.oob_present = BT_SMP_OOB_NOT_PRESENT,
	};

	sc_supported = le_sc_supported();
#if defined(CONFIG_BLUETOOTH_SMP_SC_ONLY)
	if (!sc_supported) {
		BT_ERR("SC Only Mode selected but LE SC not supported");
		return -ENOENT;
	}
#endif /* CONFIG_BLUETOOTH_SMP_SC_ONLY */

	nble_gap_sm_config_req(&params);

	memset(bt_smp_pool, 0, sizeof(bt_smp_pool));

	return smp_self_test();
}

int bt_smp_remove_info(const bt_addr_le_t *addr)
{
	struct nble_gap_sm_clear_bond_req_params params = {{0},};

	params.addr = *addr;

	nble_gap_sm_clear_bonds_req(&params);

	return 0;
}

void on_nble_gap_sm_common_rsp(const struct nble_gap_sm_response *rsp)
{
	if (rsp->status) {
		BT_INFO("gap sm request failed: %d", rsp->status);
		if (rsp->conn) {
			struct bt_smp *smp = smp_chan_get(rsp->conn);

			/* pairing has been ongoing, inform about failure */
			if (atomic_test_and_clear_bit(
					&smp->flags, SMP_FLAG_PAIRING)) {
				bt_auth->cancel(rsp->conn);
			}
		}
	}
}

void on_nble_gap_sm_config_rsp(struct nble_gap_sm_config_rsp *p_params)
{
	if (p_params->status) {
		BT_ERR("sm_config failed: %d", p_params->status);
	}
}
