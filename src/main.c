/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Thread mesh with mDNS + messaging — ESP32-C6
 * =============================================
 *
 * Extends the BLE + OpenThread provisioning app with:
 *   - mDNS hostname registration  (<name>.local → our IPv6 addresses)
 *   - mDNS-backed name resolution (resolve <name>.local → peer IPv6)
 *   - In-memory DNS cache (LRU or FIFO, configurable size and TTL)
 *   - UDP mesh messaging between nodes
 *
 * Each device gets a name (device1 / device2 / device3) stored in NVS.
 * The name is used as the mDNS hostname advertised on the Thread interface.
 *
 * Shell commands:
 *
 *   Provisioning (same flow as ble_ot_esp32c6):
 *     mesh start_leader   — Node 1: create Thread network, expose dataset via BLE
 *     mesh start_broker   — Node 3: fetch dataset from N1, push to N2
 *     mesh start_joiner   — Node 2: join Thread (BLE provisioning if needed)
 *     mesh reset          — clear stored provisioning flag
 *
 *   Identity:
 *     mesh name                  — print current hostname
 *     mesh name <device1|...>    — set hostname (persisted in NVS)
 *
 *   Messaging:
 *     mesh send <hostname.local> <message>   — resolve and send UDP message
 *
 *   Diagnostics:
 *     mesh status          — Thread role, hostname, IPv6 addresses
 *     mesh cache           — dump DNS cache
 *     mesh cache clear     — flush DNS cache
 */

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
/* nn_pal/openthread.h is OS-agnostic now: include the Zephyr OpenThread
 * context API (openthread_get_default_context, API mutex) directly. */
#include <zephyr/net/openthread.h>
#include <nn_pal/openthread.h>
#include <zephyr/net/socket.h>

#include <openthread/thread.h>
#include <openthread/dataset.h>
#include <nn_pal/ble.h>
#include <openthread/link.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_stats.h>
#include <openthread/thread_ftd.h>  /* otThreadSetRouterEligible (leaf-only policy) */

#include <errno.h>

#include <nn_osal/osal.h>
#include <nn_pal/mdns.h>
#include <node_mgr/init_manager.h>
#include <node_mgr/network_manager.h>
#include <node_mgr/provision_manager.h>
#include <node_mgr/hub_crypto.h>
#include <fw_common/nn_session.h>
#include <node_mgr/nn_session_boot.h>
#include <node_mgr/ota_client.h>
#include <nn_pal/dfu.h>
#include <node_mgr/coap_log.h>
#include <node_mgr/auto_engine.h>
#include <math.h>
#include <node_mgr/time_sync.h>
#include <zephyr/sys/base64.h>
#include <zephyr/drivers/led_strip.h>

#include <node_mgr/dns_cache.h>
#include <node_mgr/messenger.h>
#include <node_mgr/nn_proto_client.h>
#if defined(CONFIG_NODE_MGR_BUTTON)
#include <node_mgr/button.h>
#endif

NN_OSAL_LOG_MODULE(main);

/* ── device name — persisted in NVS via Zephyr settings ─────────── */

static char g_device_name[CONFIG_APP_HOSTNAME_SIZE];

static int name_kv_load(const char *key_suffix, const uint8_t *value,
			size_t value_len, void *user)
{
	NN_OSAL_UNUSED(user);
	if (strcmp(key_suffix, "name") == 0 && value_len > 0) {
		size_t n = value_len;
		if (n >= sizeof(g_device_name)) {
			n = sizeof(g_device_name) - 1;
		}
		memcpy(g_device_name, value, n);
		g_device_name[n] = '\0';
	}
	return 0;
}

static void apply_device_name(const char *name)
{
	strncpy(g_device_name, name, sizeof(g_device_name) - 1);
	g_device_name[sizeof(g_device_name) - 1] = '\0';

	/* Tell mDNS responder about the new hostname */
	nn_pal_mdns_set_hostname(g_device_name);

	NN_LOG_INF("hostname set to '%s' (.local suffix added by mDNS)", g_device_name);
}

static void save_device_name(void)
{
	nn_osal_kv_save("mesh_app/name",
			g_device_name, strlen(g_device_name) + 1);
}

/* ── role helpers ────────────────────────────────────────────────── */

static const char *role_str(otDeviceRole r)
{
	switch (r) {
	case OT_DEVICE_ROLE_DISABLED: return "disabled";
	case OT_DEVICE_ROLE_DETACHED: return "detached";
	case OT_DEVICE_ROLE_CHILD:    return "child";
	case OT_DEVICE_ROLE_ROUTER:   return "router";
	case OT_DEVICE_ROLE_LEADER:   return "leader";
	default:                      return "unknown";
	}
}

/* ── shell: provisioning commands ────────────────────────────────── */

static int cmd_start_leader(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (!nm_is_ready()) {
		nn_osal_shell_error(sh, "Network manager not ready");
		return -ENODEV;
	}

	nn_osal_shell_print(sh, "=== Leader: creating Thread network ===");

	int rc = nm_thread_create_network();
	if (rc) {
		nn_osal_shell_error(sh, "nm_thread_create_network: %d", rc);
		return rc;
	}

	nn_osal_shell_print(sh, "Waiting for Leader role (max 90 s)...");
	rc = nm_thread_wait_for_role(OT_DEVICE_ROLE_LEADER, 90000);
	if (rc) {
		nn_osal_shell_error(sh, "Not Leader after 90 s (role: %s)",
			    role_str(nm_thread_get_role()));
		return rc;
	}
	nn_osal_shell_print(sh, "Thread role: leader");

	uint8_t tlvs[OT_OPERATIONAL_DATASET_MAX_LENGTH];
	uint8_t tlv_len = 0;
	rc = nm_thread_get_dataset(tlvs, &tlv_len);
	if (rc) {
		nn_osal_shell_error(sh, "nm_thread_get_dataset: %d", rc);
		return rc;
	}

	prov_set_leader_dataset(tlvs, tlv_len);
	rc = prov_peripheral_start();
	if (rc) {
		nn_osal_shell_error(sh, "prov_peripheral_start: %d", rc);
		return rc;
	}

	nn_osal_shell_print(sh, "Advertising dataset — run 'mesh start_broker' on Node 3.");
	return 0;
}

static int cmd_start_broker(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (!nm_is_ready()) {
		nn_osal_shell_error(sh, "Network manager not ready");
		return -ENODEV;
	}

	nn_osal_shell_print(sh, "=== Broker: fetch from leader, push to joiner ===");

	uint8_t tlvs[OT_OPERATIONAL_DATASET_MAX_LENGTH];
	uint8_t tlv_len = 0;

	nn_osal_shell_print(sh, "Step 1: scanning for leader...");
	int rc = prov_central_fetch(tlvs, &tlv_len, 60000);
	if (rc) {
		nn_osal_shell_error(sh, "prov_central_fetch: %d", rc);
		return rc;
	}
	nn_osal_shell_print(sh, "Dataset fetched (%u bytes)", tlv_len);

	nn_osal_shell_print(sh, "Step 2: scanning for joiner...");
	rc = prov_central_push(tlvs, tlv_len, 60000);
	if (rc) {
		nn_osal_shell_error(sh, "prov_central_push: %d", rc);
		return rc;
	}

	nn_osal_shell_print(sh, "Joiner provisioned.");

	/* Also apply the dataset to this broker node and join Thread */
	nn_osal_shell_print(sh, "Step 3: applying dataset to broker and joining Thread...");
	rc = nm_thread_apply_dataset(tlvs, tlv_len);
	if (rc) {
		nn_osal_shell_error(sh, "nm_thread_apply_dataset: %d", rc);
		return rc;
	}
	rc = nm_thread_start();
	if (rc) {
		nn_osal_shell_error(sh, "nm_thread_start: %d", rc);
		return rc;
	}

	nn_osal_shell_print(sh, "Waiting for Thread role (max 60 s)...");
	rc = nm_thread_wait_for_role(OT_DEVICE_ROLE_CHILD, 60000);
	if (rc) {
		otDeviceRole role = nm_thread_get_role();
		if (role == OT_DEVICE_ROLE_ROUTER || role == OT_DEVICE_ROLE_LEADER) {
			rc = 0;
		}
	}
	if (rc) {
		nn_osal_shell_error(sh, "Broker did not join Thread — try 'mesh reset' then retry");
		return rc;
	}

	nn_osal_shell_print(sh, "Broker Thread role: %s — mesh ready.",
		    role_str(nm_thread_get_role()));
	return 0;
}

static int cmd_start_joiner(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (!nm_is_ready()) {
		nn_osal_shell_error(sh, "Network manager not ready");
		return -ENODEV;
	}

	nn_osal_shell_print(sh, "=== Joiner ===");

	if (!im_needs_provisioning()) {
		nn_osal_shell_print(sh, "Already provisioned — rejoining Thread...");
		int rc = nm_thread_start();
		if (rc) {
			nn_osal_shell_error(sh, "nm_thread_start: %d", rc);
			return rc;
		}

		nn_osal_shell_print(sh, "Waiting for role (max 60 s)...");
		rc = nm_thread_wait_for_role(OT_DEVICE_ROLE_CHILD, 60000);
		if (rc) {
			otDeviceRole role = nm_thread_get_role();
			if (role == OT_DEVICE_ROLE_ROUTER ||
			    role == OT_DEVICE_ROLE_LEADER) {
				rc = 0;
			}
		}
		if (rc) {
			nn_osal_shell_error(sh, "Timed out — try 'mesh reset' then retry");
			return rc;
		}
		nn_osal_shell_print(sh, "Thread role: %s", role_str(nm_thread_get_role()));
		return 0;
	}

	nn_osal_shell_print(sh, "No stored dataset — advertising for BLE provisioning...");
	nm_ble_acquire_rf();
	int rc = prov_peripheral_start();
	if (rc) {
		nn_osal_shell_error(sh, "prov_peripheral_start: %d", rc);
		return rc;
	}

	nn_osal_shell_print(sh, "Waiting for broker (max 5 min)...");
	rc = prov_peripheral_wait(5 * 60 * 1000);
	prov_peripheral_stop();

	if (rc) {
		nn_osal_shell_error(sh, "Provisioning timed out");
		return rc;
	}

	nn_osal_shell_print(sh, "Dataset applied — waiting for Thread role (max 60 s)...");
	rc = nm_thread_wait_for_role(OT_DEVICE_ROLE_CHILD, 60000);
	if (rc) {
		otDeviceRole role = nm_thread_get_role();
		if (role == OT_DEVICE_ROLE_ROUTER ||
		    role == OT_DEVICE_ROLE_LEADER) {
			rc = 0;
		}
	}
	if (rc) {
		nn_osal_shell_error(sh, "Did not join (role: %s)",
			    role_str(nm_thread_get_role()));
		return rc;
	}

	nn_osal_shell_print(sh, "Thread role: %s — provisioning complete.",
		    role_str(nm_thread_get_role()));
	return 0;
}

static int cmd_reset(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	im_clear_provisioning();
	nn_osal_shell_print(sh, "Provisioned flag cleared — Thread stopped.");
	return 0;
}

/* ── shell: identity commands ────────────────────────────────────── */

static int cmd_name(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		/* Print current name */
		nn_osal_shell_print(sh, "hostname: %s  (.local: %s.local)",
			    g_device_name, g_device_name);
		return 0;
	}

	const char *new_name = argv[1];
	if (strlen(new_name) == 0 || strlen(new_name) >= CONFIG_APP_HOSTNAME_SIZE) {
		nn_osal_shell_error(sh, "Name must be 1-%d chars",
			    CONFIG_APP_HOSTNAME_SIZE - 1);
		return -EINVAL;
	}

	apply_device_name(new_name);
	save_device_name();
	nn_osal_shell_print(sh, "Hostname set to '%s.local' and saved to NVS.", g_device_name);
	return 0;
}

/* ── shell: set hub pubkey directly (bypass BLE provisioning) ─────── */

static int cmd_set_hub_pub(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc != 2 || strlen(argv[1]) != 64) {
		nn_osal_shell_error(sh, "usage: mesh set-hub-pub <hex64>  (32 bytes)");
		return -EINVAL;
	}
	uint8_t pub[32];
	for (int i = 0; i < 32; i++) {
		char b[3] = { argv[1][2*i], argv[1][2*i+1], 0 };
		char *end;
		long v = strtol(b, &end, 16);
		if (end != b + 2 || v < 0 || v > 255) {
			nn_osal_shell_error(sh, "bad hex at byte %d", i);
			return -EINVAL;
		}
		pub[i] = (uint8_t)v;
	}
	int rc = hub_crypto_set_hub_pubkey(pub);
	if (rc) {
		nn_osal_shell_error(sh, "hub_crypto_set_hub_pubkey: %d", rc);
		return rc;
	}
	nn_osal_shell_print(sh, "hub pubkey set + persisted to NVS");
	return 0;
}

/* ── shell: status ───────────────────────────────────────────────── */

/* delivery-probe receipts per cell (cmd 0x0F70..0x0F7F), shown by
 * `mesh status` */
static uint32_t g_probe_rx[16];

static int cmd_status(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	nn_osal_shell_print(sh, "Hostname       : %s.local", g_device_name);
	nn_osal_shell_print(sh, "Thread role    : %s", role_str(nm_thread_get_role()));
	nn_osal_shell_print(sh, "BLE provisioned: %s",
		    prov_is_provisioned() ? "yes" : "no");
	nn_osal_shell_print(sh, "NM ready       : %s", nm_is_ready() ? "yes" : "no");
	nn_osal_shell_print(sh, "Bluetooth      : %s", nn_pal_ble_is_ready() ? "ON" : "off");

	/* Mesh position: who this node hangs off and how well it hears it.
	 * A child's RLOC16 carries its parent's router id in the top 6 bits
	 * (router = id << 10), so it can be matched to a gateway's RLOC16. */
	{
		struct openthread_context *octx = openthread_get_default_context();
		otInstance *ot = openthread_get_default_instance();
		otRouterInfo parent;
		int8_t prssi = 0;
		uint16_t rloc = 0;
		bool have_parent = false;
		openthread_api_mutex_lock(octx);
		rloc = otThreadGetRloc16(ot);
		if (otThreadGetParentInfo(ot, &parent) == OT_ERROR_NONE) {
			have_parent = true;
			(void)otThreadGetParentAverageRssi(ot, &prssi);
		}
		openthread_api_mutex_unlock(octx);
		nn_osal_shell_print(sh, "RLOC16         : 0x%04x (router id %u)",
				    rloc, rloc >> 10);
		openthread_api_mutex_lock(octx);
		uint8_t chan = otLinkGetChannel(ot);
		otOperationalDataset pend;
		bool has_pend = otDatasetGetPending(ot, &pend) == OT_ERROR_NONE;
		openthread_api_mutex_unlock(octx);
		if (has_pend && pend.mComponents.mIsChannelPresent) {
			nn_osal_shell_print(sh, "Channel        : %u (pending -> %u, delay %u ms)", chan,
					    pend.mChannel, pend.mComponents.mIsDelayPresent ? pend.mDelay : 0);
		} else {
			nn_osal_shell_print(sh, "Channel        : %u", chan);
		}
		if (have_parent) {
			nn_osal_shell_print(sh, "Parent         : 0x%04x (router id %u) "
					    "rssi %d dBm lq in/out %u/%u age %us",
					    parent.mRloc16, parent.mRouterId, prssi,
					    parent.mLinkQualityIn, parent.mLinkQualityOut,
					    parent.mAge);
		} else {
			nn_osal_shell_print(sh, "Parent         : (none)");
		}
	}

	/* Receive path, bottom to top, for delivery experiments: radio (MAC)
	 * -> OpenThread IPv6 -> Zephyr IPv6/UDP -> app (probe counters). */
	{
		struct openthread_context *octx = openthread_get_default_context();
		otInstance *ot = openthread_get_default_instance();
		openthread_api_mutex_lock(octx);
		const otMacCounters *mc = otLinkGetCounters(ot);
		const otIpCounters *ic = otThreadGetIp6Counters(ot);
		uint32_t rxUni = mc->mRxUnicast, rxData = mc->mRxData, rxDup = mc->mRxDuplicated,
			 rxSec = mc->mRxErrSec, rxUnk = mc->mRxErrUnknownNeighbor,
			 rxOther = mc->mRxErrOther, rxFcs = mc->mRxErrFcs;
		uint32_t ipRxOk = ic->mRxSuccess, ipRxFail = ic->mRxFailure;
		openthread_api_mutex_unlock(octx);
		nn_osal_shell_print(sh, "MAC rx         : uni=%u data=%u dup=%u errSec=%u errUnkNbr=%u errFcs=%u errOther=%u",
				    rxUni, rxData, rxDup, rxSec, rxUnk, rxFcs, rxOther);
		nn_osal_shell_print(sh, "OT IPv6 rx     : ok=%u fail=%u", ipRxOk, ipRxFail);
	}
#if defined(CONFIG_NET_STATISTICS)
	{
		struct net_stats st;
		if (net_mgmt(NET_REQUEST_STATS_GET_ALL, NULL, &st, sizeof st) == 0) {
			nn_osal_shell_print(sh, "Zephyr IPv6    : recv=%u drop=%u | UDP recv=%u drop=%u chkerr=%u",
					    st.ipv6.recv, st.ipv6.drop, st.udp.recv, st.udp.drop, st.udp.chkerr);
		}
	}
#endif
	{
		struct k_mem_slab *rx, *tx; struct net_buf_pool *rxd, *txd;
		net_pkt_get_info(&rx, &tx, &rxd, &txd);
		nn_osal_shell_print(sh, "RX pools free  : pkt=%u/%u buf=%u/%u",
				    k_mem_slab_num_free_get(rx), rx->info.num_blocks,
				    (unsigned)atomic_get(&rxd->avail_count), rxd->buf_count);
	}
	{
		char pb[160]; int off = 0;
		for (int i = 0; i < 16; i++)
			if (g_probe_rx[i])
				off += snprintf(pb + off, sizeof pb - off, " c%d=%u", i, g_probe_rx[i]);
		nn_osal_shell_print(sh, "Probes rx      :%s", off ? pb : " none");
		uint32_t rs = 0, rl = 0;
		nn_proto_client_raw_probe_counts(&rs, &rl);
		nn_osal_shell_print(sh, "Raw probes rx  : small=%u large=%u", rs, rl);
	}
	{
		/* radio driver: transmit outcomes by HAL error code */
		/* from the driver fix, nn-modules patches/zephyr/0001; weak so a
		 * build on an unpatched Zephyr still links (line then omitted) */
		extern uint32_t nn_esp32_tx_outcome[16] __attribute__((weak));
		const uint32_t *o = nn_esp32_tx_outcome;
		if (o) {
			nn_osal_shell_print(sh, "Radio TX       : ok=%u ccaBusy=%u abort=%u noAck=%u badAck=%u coex=%u sec=%u",
					    o[0], o[1 + 1], o[1 + 2], o[1 + 3], o[1 + 4], o[1 + 5], o[1 + 6]);
		}
		struct openthread_context *octx = openthread_get_default_context();
		otInstance *ot = openthread_get_default_instance();
		openthread_api_mutex_lock(octx);
		const otMacCounters *mc = otLinkGetCounters(ot);
		const otMleCounters *ml = otThreadGetMleCounters(ot);
		uint32_t v[12] = { mc->mRxTotal, mc->mRxUnicast, mc->mRxAddressFiltered, mc->mRxDestAddrFiltered,
				   mc->mRxErrNoFrame, mc->mRxErrOther, mc->mTxTotal, mc->mTxRetry,
				   ml->mParentChanges, ml->mAttachAttempts, ml->mDetachedRole, ml->mChildRole };
		openthread_api_mutex_unlock(octx);
		nn_osal_shell_print(sh, "OT MAC         : rxTotal=%u rxUni=%u addrFilt=%u dstFilt=%u noFrame=%u other=%u | txTotal=%u txRetry=%u",
				    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
		nn_osal_shell_print(sh, "OT MLE         : parentChanges=%u attachAttempts=%u detached=%u child=%u",
				    v[8], v[9], v[10], v[11]);
	}

	/* Print all IPv6 addresses on the OT interface */
	struct net_if *iface =
		net_if_get_first_by_type(&NET_L2_GET_NAME(OPENTHREAD));
	if (iface) {
		char addr_str[NET_IPV6_ADDR_LEN];
		struct net_if_ipv6 *ipv6 = iface->config.ip.ipv6;
		if (ipv6) {
			nn_osal_shell_print(sh, "IPv6 addresses :");
			for (int i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
				if (!ipv6->unicast[i].is_used) {
					continue;
				}
				net_addr_ntop(AF_INET6,
					      &ipv6->unicast[i].address.in6_addr,
					      addr_str, sizeof(addr_str));
				nn_osal_shell_print(sh, "  %s", addr_str);
			}
		}
	}
	return 0;
}


/* ── shell: energy scan (diagnostics) ─────────────────────────────────
 * `mesh scan [ms]` -- OpenThread energy scan of channels 11..26 from THIS
 * device's position: max RSSI per channel.  The channel-busy (CCA) rate
 * this radio sees is about energy at the device, which a scan from a
 * gateway elsewhere cannot show. */
static int8_t s_scan_max[27];
static volatile bool s_scan_done;

static void energy_scan_cb(otEnergyScanResult *r, void *ctx)
{
	ARG_UNUSED(ctx);
	if (!r) { s_scan_done = true; return; }
	if (r->mChannel >= 11 && r->mChannel <= 26) s_scan_max[r->mChannel] = r->mMaxRssi;
}

static int cmd_scan(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	uint16_t ms = argc > 1 ? (uint16_t)atoi(argv[1]) : 500;
	struct openthread_context *octx = openthread_get_default_context();
	otInstance *ot = openthread_get_default_instance();
	for (int c = 11; c <= 26; c++) s_scan_max[c] = 127;
	s_scan_done = false;
	openthread_api_mutex_lock(octx);
	otError e = otLinkEnergyScan(ot, 0x07fff800 /* ch 11-26 */, ms, energy_scan_cb, NULL);
	openthread_api_mutex_unlock(octx);
	if (e != OT_ERROR_NONE) { nn_osal_shell_error(sh, "otLinkEnergyScan: %d", e); return -EIO; }
	for (int t = 0; t < 16 * ms / 100 + 60 && !s_scan_done; t++) k_msleep(100);
	char line[200]; int off = 0;
	for (int c = 11; c <= 26; c++) off += snprintf(line + off, sizeof line - off, " %d:%d", c, s_scan_max[c]);
	nn_osal_shell_print(sh, "Energy scan    :%s", line);
	return 0;
}

/* ── shell: send ─────────────────────────────────────────────────── */

static int cmd_send(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc < 3) {
		nn_osal_shell_error(sh, "Usage: mesh send <hostname.local> <message>");
		return -EINVAL;
	}

	const char *hostname = argv[1];
	const char *message  = argv[2];

	nn_osal_shell_print(sh, "Sending to %s: \"%s\"", hostname, message);

	int rc = messenger_send(hostname, message);
	if (rc == -EHOSTUNREACH) {
		nn_osal_shell_error(sh, "Cannot resolve %s — is the peer up?", hostname);
	} else if (rc != 0) {
		nn_osal_shell_error(sh, "Send failed: %d", rc);
	} else {
		nn_osal_shell_print(sh, "Sent.");
	}
	return rc;
}

/* ── shell: cache ────────────────────────────────────────────────── */

static int cmd_cache(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "clear") == 0) {
		dns_cache_clear();
		nn_osal_shell_print(sh, "DNS cache cleared.");
		return 0;
	}
	dns_cache_dump();
	return 0;
}

/* ── shell: ota ──────────────────────────────────────────────────── */

static int cmd_ota(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		nn_osal_shell_print(sh, "Usage: mesh ota <check|download|apply|confirm|status|hub|auto-apply>");
		return -EINVAL;
	}

	const char *sub = argv[1];

	if (strcmp(sub, "status") == 0) {
		nn_osal_shell_print(sh, "Firmware  : %s (%s)", nn_osal_app_version(),
			    CONFIG_APP_DEVICE_TYPE);
		{
			nn_pal_dfu_state_t dst = NN_PAL_DFU_STATE_UNKNOWN;
			(void)nn_pal_dfu_get_state(&dst);
			nn_osal_shell_print(sh, "Confirmed : %s",
				    dst == NN_PAL_DFU_STATE_RUNNING_CONFIRMED
					? "yes" : "no (test)");
		}
		const char *pv = ota_client_pending_version();
		if (pv[0]) {
			nn_osal_shell_print(sh, "Pending  : %s (%u B)", pv,
				    ota_client_pending_size());
		} else {
			nn_osal_shell_print(sh, "Pending  : (none)");
		}
		nn_osal_shell_print(sh, "Hub addr : %s",
			    ota_client_get_hub_addr()[0]
			    ? ota_client_get_hub_addr() : "(unset)");
		nn_osal_shell_print(sh, "Auto-apply: %s",
			    ota_client_get_auto_apply() ? "on" : "off");
		return 0;
	}

	if (strcmp(sub, "hub") == 0) {
		if (argc < 3) {
			nn_osal_shell_print(sh, "Hub: %s",
				    ota_client_get_hub_addr()[0]
				    ? ota_client_get_hub_addr() : "(unset)");
			return 0;
		}
		return ota_client_set_hub_addr(argv[2]);
	}

	if (strcmp(sub, "auto-apply") == 0) {
		if (argc < 3) {
			nn_osal_shell_print(sh, "Auto-apply: %s",
				    ota_client_get_auto_apply() ? "on" : "off");
			return 0;
		}
		ota_client_set_auto_apply(strcmp(argv[2], "on") == 0);
		nn_osal_shell_print(sh, "Auto-apply: %s",
			    ota_client_get_auto_apply() ? "on" : "off");
		return 0;
	}

	if (strcmp(sub, "check") == 0) {
		int rc = ota_client_check();
		if (rc < 0) {
			nn_osal_shell_error(sh, "Check failed: %d", rc);
		} else if (rc == 0) {
			nn_osal_shell_print(sh, "Up to date: %s",
				    nn_osal_app_version());
		} else {
			nn_osal_shell_print(sh, "Update available: %s (%u B)",
				    ota_client_pending_version(),
				    ota_client_pending_size());
		}
		return rc < 0 ? rc : 0;
	}

	if (strcmp(sub, "download") == 0) {
		int rc = ota_client_download();
		if (rc < 0) {
			nn_osal_shell_error(sh, "Download failed: %d", rc);
		} else {
			nn_osal_shell_print(sh, "Download complete — 'mesh ota apply' to install");
			if (ota_client_get_auto_apply()) {
				nn_osal_shell_print(sh, "Auto-apply enabled — applying now...");
				ota_client_apply();
			}
		}
		return rc;
	}

	if (strcmp(sub, "apply") == 0) {
		nn_osal_shell_print(sh, "Applying test update and rebooting...");
		nn_osal_shell_print(sh, "Run 'mesh ota confirm' after reboot to make permanent");
		return ota_client_apply();
	}

	if (strcmp(sub, "confirm") == 0) {
		int rc = ota_client_confirm();
		if (rc < 0) {
			nn_osal_shell_error(sh, "Confirm failed: %d", rc);
		} else {
			nn_osal_shell_print(sh, "Image confirmed as permanent");
		}
		return rc;
	}

	nn_osal_shell_error(sh, "Unknown: %s", sub);
	return -EINVAL;
}

/* ── shell: log ──────────────────────────────────────────────────── */

static int cmd_log(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		nn_osal_shell_print(sh, "Usage: mesh log <on|off>");
		return -EINVAL;
	}
	if (strcmp(argv[1], "on") == 0) {
		const char *hub = ota_client_get_hub_addr();
		if (!hub || hub[0] == '\0') {
			nn_osal_shell_error(sh, "No hub address — set with 'mesh ota hub <addr>'");
			return -ENOENT;
		}
		int rc = coap_log_start(hub);
		if (rc < 0) {
			nn_osal_shell_error(sh, "coap_log_start: %d", rc);
			return rc;
		}
		nn_osal_shell_print(sh, "Remote logging enabled → %s", hub);
	} else if (strcmp(argv[1], "off") == 0) {
		coap_log_stop();
		nn_osal_shell_print(sh, "Remote logging disabled");
	} else {
		nn_osal_shell_error(sh, "Usage: mesh log <on|off>");
		return -EINVAL;
	}
	return 0;
}

/* ── shell: auto ─────────────────────────────────────────────────── */

static int cmd_auto(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		nn_osal_shell_print(sh, "Usage: mesh auto <status|set|get> [args]");
		return -EINVAL;
	}

	if (strcmp(argv[1], "status") == 0) {
		nn_osal_shell_print(sh, "Rules loaded: %d", auto_engine_rule_count());
		return 0;
	}

	if (strcmp(argv[1], "load-bin") == 0) {
		if (argc < 3) {
			nn_osal_shell_print(sh, "Usage: mesh auto load-bin <base64>");
			return -EINVAL;
		}
		/* Decode base64 */
		uint8_t bin[1200];
		size_t bin_len = sizeof(bin);
		int rc = base64_decode(bin, sizeof(bin), &bin_len,
				       argv[2], strlen(argv[2]));
		if (rc < 0) {
			nn_osal_shell_error(sh, "base64 decode: %d", rc);
			return rc;
		}
		rc = auto_engine_load(bin, bin_len);
		if (rc < 0) {
			nn_osal_shell_error(sh, "load: %d", rc);
			return rc;
		}
		nn_osal_shell_print(sh, "Loaded %d rules from %zu bytes",
			    auto_engine_rule_count(), bin_len);
		return 0;
	}

	if (strcmp(argv[1], "set") == 0) {
		if (argc < 4) {
			nn_osal_shell_print(sh, "Usage: mesh auto set <field> <value>");
			return -EINVAL;
		}
		float val = strtof(argv[3], NULL);
		auto_engine_set_field(argv[2], val);
		nn_osal_shell_print(sh, "%s = %.2f", argv[2], (double)val);
		return 0;
	}

	if (strcmp(argv[1], "get") == 0) {
		if (argc < 3) {
			nn_osal_shell_print(sh, "Usage: mesh auto get <field>");
			return -EINVAL;
		}
		float val = auto_engine_get_field(argv[2]);
		if (isnan(val)) {
			nn_osal_shell_print(sh, "%s = (not set)", argv[2]);
		} else {
			nn_osal_shell_print(sh, "%s = %.2f", argv[2], (double)val);
		}
		return 0;
	}

	nn_osal_shell_error(sh, "Unknown: %s", argv[1]);
	return -EINVAL;
}

/* ── shell: time ─────────────────────────────────────────────────── */

static int cmd_time(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "sync") == 0) {
		nn_osal_shell_print(sh, "Syncing with hub...");
		int rc = time_sync_once();
		if (rc < 0) {
			nn_osal_shell_error(sh, "Sync failed: %d", rc);
			return rc;
		}
		nn_osal_shell_print(sh, "Synced.");
	}

	int64_t now = time_sync_now_ms();
	int64_t age = time_sync_age_ms();
	bool valid = time_sync_is_valid();

	nn_osal_shell_print(sh, "Wall clock: %lld ms%s",
		    now, valid ? "" : " (not synced)");
	nn_osal_shell_print(sh, "Uptime:     %lld ms", (int64_t)nn_osal_uptime_ms());
	if (valid) {
		nn_osal_shell_print(sh, "Sync age:   %lld ms", age);
	}
	return 0;
}

/* ── shell registration ──────────────────────────────────────────── */

/* Diagnostic: isolate deferred-log crash — is NN_LOG_ERR broken for
 * every module or only ota_client? */
static int cmd_logtest(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(sh); NN_OSAL_UNUSED(argc);
	if (argc < 2) {
		printk("logtest: usage: mesh logtest <inf|wrn|err>\n");
		return 0;
	}
	if (strcmp(argv[1], "inf") == 0) {
		NN_LOG_INF("logtest INF from main");
	} else if (strcmp(argv[1], "wrn") == 0) {
		NN_LOG_WRN("logtest WRN from main");
	} else if (strcmp(argv[1], "err") == 0) {
		NN_LOG_ERR("logtest ERR from main");
	} else if (strcmp(argv[1], "ota-inf") == 0) {
		ota_client_logtest("inf");
	} else if (strcmp(argv[1], "ota-wrn") == 0) {
		ota_client_logtest("wrn");
	} else if (strcmp(argv[1], "ota-err") == 0) {
		ota_client_logtest("err");
	} else {
		printk("unknown: %s\n", argv[1]);
	}
	printk("logtest: returned from LOG_*\n");
	return 0;
}

/* UDP reliability diagnostic: send CoAP POST /ping to the hub N
 * times, measure success vs fail.  Two modes:
 *   mesh udptest reuse <N>  — open ONE socket, N request/response cycles
 *   mesh udptest fresh <N>  — open+close a new socket per cycle
 * Isolates the "zsock recvfrom stops waking after first packet"
 * hypothesis.  Hub is at 64:ff9b::c0a8:32e7:5683.  CoAP POST /ping
 * returns a 37-byte 2.05 reply within ~50 ms when the path is clean. */
static int find_omr_main(struct in6_addr *out)
{
	struct net_if *iface = net_if_get_default();
	struct net_if_ipv6 *ipv6 = iface ? iface->config.ip.ipv6 : NULL;
	if (!ipv6) return -ENODEV;
	for (int i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
		struct net_if_addr *a = &ipv6->unicast[i];
		if (!a->is_used) continue;
		const uint8_t *b = a->address.in6_addr.s6_addr;
		if (b[0] == 0xfd && b[1] == 0xc0 && b[2] == 0xfa &&
		    b[3] == 0xce && b[4] == 0xb0 && b[5] == 0x0c) {
			*out = a->address.in6_addr;
			return 0;
		}
	}
	return -ENOENT;
}

/* POST /ota/check with JSON — hub replies with ~141-byte JSON.
 * This mimics ota_client_check's packet, so we can test whether
 * the 6LoWPAN-fragmented reply is what wedges zsock RX. */
static int build_ping(uint8_t *buf, size_t cap, uint16_t seq)
{
	if (cap < 80) return -1;
	const char *json = "{\"type\":\"sample_c6\",\"version\":\"0.0.0\"}";
	size_t jlen = strlen(json);
	size_t i = 0;
	buf[i++] = 0x42;              /* ver=1 type=CON tkl=2 */
	buf[i++] = 0x02;              /* POST */
	buf[i++] = (seq >> 8) & 0xff;
	buf[i++] = seq & 0xff;
	buf[i++] = (seq >> 8) & 0xff; /* 2-byte token = seq */
	buf[i++] = seq & 0xff;
	/* Uri-Path "ota" (11, len 3) */
	buf[i++] = 0xB3;
	buf[i++] = 'o'; buf[i++] = 't'; buf[i++] = 'a';
	/* Uri-Path "check" (delta 0, len 5) */
	buf[i++] = 0x05;
	buf[i++] = 'c'; buf[i++] = 'h'; buf[i++] = 'e'; buf[i++] = 'c'; buf[i++] = 'k';
	/* Content-Format 50 (delta 1, len 1) */
	buf[i++] = 0x11;
	buf[i++] = 50;
	/* Payload marker */
	buf[i++] = 0xFF;
	memcpy(buf + i, json, jlen);
	i += jlen;
	return (int)i;
}

static int open_zsock_to_dest(struct sockaddr_in6 *dst,
			      const char *addr, uint16_t port)
{
	int sock = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) return -errno;
	struct sockaddr_in6 local = {
		.sin6_family = AF_INET6, .sin6_port = 0,
		.sin6_addr = IN6ADDR_ANY_INIT,
	};
	find_omr_main(&local.sin6_addr);  /* bind to OMR if we have one */
	zsock_bind(sock, (struct sockaddr *)&local, sizeof(local));
	memset(dst, 0, sizeof(*dst));
	dst->sin6_family = AF_INET6;
	dst->sin6_port = htons(port);
	if (zsock_inet_pton(AF_INET6, addr, &dst->sin6_addr) != 1) {
		zsock_close(sock);
		return -EINVAL;
	}
	struct zsock_timeval tv = { .tv_sec = 4 };
	zsock_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return sock;
}

static int open_zsock_to_hub(struct sockaddr_in6 *hub)
{
	return open_zsock_to_dest(hub, "64:ff9b::c0a8:32e7", 5683);
}

static int udp_one_cycle(int sock, const struct sockaddr_in6 *hub,
			 uint16_t seq)
{
	uint8_t req[128], resp[512];
	int rlen = build_ping(req, sizeof(req), seq);
	ssize_t n = zsock_sendto(sock, req, rlen, 0,
				 (const struct sockaddr *)hub, sizeof(*hub));
	if (n < 0) return -errno;
	n = zsock_recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
	if (n < 0) return -errno;
	return (int)n;
}

static int cmd_udptest(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(sh);
	if (argc < 3) {
		printk("usage: mesh udptest <reuse|fresh> <N> [addr port]\n"
		       "  default target: hub 64:ff9b::c0a8:32e7:5683\n");
		return 0;
	}
	int n = atoi(argv[2]);
	if (n <= 0 || n > 200) n = 10;

	const char *addr = (argc >= 4) ? argv[3] : "64:ff9b::c0a8:32e7";
	uint16_t port    = (argc >= 5) ? (uint16_t)atoi(argv[4]) : 5683;

	bool reuse = (strcmp(argv[1], "reuse") == 0);
	struct sockaddr_in6 hub;
	int sock = -1;
	int ok = 0, fail = 0;
	uint32_t t_total = 0;

	printk("udptest target: %s:%u  mode:%s  N:%d\n",
	       addr, port, argv[1], n);

	if (reuse) {
		sock = open_zsock_to_dest(&hub, addr, port);
		if (sock < 0) {
			printk("udptest: open err %d\n", -sock);
			return 0;
		}
		printk("udptest reuse: opened sock=%d\n", sock);
	} else {
		/* fresh mode needs dest sockaddr filled (sock opened per cycle) */
		memset(&hub, 0, sizeof(hub));
		hub.sin6_family = AF_INET6;
		hub.sin6_port = htons(port);
		zsock_inet_pton(AF_INET6, addr, &hub.sin6_addr);
	}

	for (int i = 0; i < n; i++) {
		uint32_t t0 = nn_osal_uptime_ms_32();
		int r;
		if (reuse) {
			r = udp_one_cycle(sock, &hub, (uint16_t)(i + 1));
		} else {
			int s = open_zsock_to_dest(&hub, addr, port);
			if (s < 0) { fail++; printk("[%d] open err %d\n", i, -s); continue; }
			r = udp_one_cycle(s, &hub, (uint16_t)(i + 1));
			zsock_close(s);
		}
		uint32_t dt = nn_osal_uptime_ms_32() - t0;
		t_total += dt;
		if (r > 0) {
			ok++;
			printk("[%d] ok %d B in %u ms\n", i, r, (unsigned)dt);
		} else {
			fail++;
			printk("[%d] FAIL %d after %u ms\n", i, r, (unsigned)dt);
		}
		nn_osal_sleep_ms(50);  /* small gap between cycles */
	}
	if (reuse) zsock_close(sock);
	printk("udptest %s: %d/%d ok, %d fail, avg %u ms\n",
	       argv[1], ok, n, fail, (unsigned)(t_total / n));
	return 0;
}

NN_OSAL_SHELL_SUBCMD_SET_CREATE(mesh_cmds,
	NN_OSAL_SHELL_CMD_ARG(logtest, cmd_logtest,
		"NN_LOG_INF/WRN/ERR (diag)", 1, 1),
	NN_OSAL_SHELL_CMD_ARG(udptest, cmd_udptest,
		"mesh udptest <reuse|fresh> <N> [addr port]", 3, 2),
	/* Provisioning */
	NN_OSAL_SHELL_CMD(start_leader, cmd_start_leader,
		"Create Thread network and expose dataset via BLE"),
	NN_OSAL_SHELL_CMD(start_broker, cmd_start_broker,
		"BLE broker: fetch dataset from leader, push to joiner"),
	NN_OSAL_SHELL_CMD(start_joiner, cmd_start_joiner,
		"Join Thread (BLE provisioning if no stored dataset)"),
	NN_OSAL_SHELL_CMD(reset, cmd_reset,
		"Clear provisioning flag and stop Thread"),
	/* Identity */
	NN_OSAL_SHELL_CMD_ARG(name, cmd_name,
		"Get or set mDNS hostname  (mesh name [device1|device2|device3])",
		1, 1),
	/* Messaging */
	NN_OSAL_SHELL_CMD_ARG(send, cmd_send,
		"Send UDP message  (mesh send <hostname.local> <message>)",
		3, 0),
	/* Diagnostics */
	NN_OSAL_SHELL_CMD_ARG(scan, cmd_scan,
		"Energy scan ch 11-26 from this device: mesh scan [ms]", 1, 1),
	NN_OSAL_SHELL_CMD(status, cmd_status,
		"Show Thread role, hostname, and IPv6 addresses"),
	NN_OSAL_SHELL_CMD_ARG(set-hub-pub, cmd_set_hub_pub,
		"Set hub X25519 pubkey (hex64) — bypass BLE for relay testing",
		2, 0),
	NN_OSAL_SHELL_CMD_ARG(cache, cmd_cache,
		"Show DNS cache  (mesh cache [clear])", 1, 1),
	/* OTA */
	NN_OSAL_SHELL_CMD_ARG(ota, cmd_ota,
		"OTA firmware update  (mesh ota <check|download|apply|status|hub|auto-apply>)",
		2, 2),
	/* Remote logging */
	NN_OSAL_SHELL_CMD_ARG(log, cmd_log,
		"Remote log to hub  (mesh log <on|off>)", 2, 0),
	/* Automation */
	NN_OSAL_SHELL_CMD_ARG(auto, cmd_auto,
		"Automation engine  (mesh auto <status|set|get> [args])",
		2, 3),
	/* Time sync */
	NN_OSAL_SHELL_CMD_ARG(time, cmd_time,
		"Wall-clock time  (mesh time [sync])", 1, 1),
	NN_OSAL_SHELL_SUBCMD_SET_END
);

NN_OSAL_SHELL_CMD_REGISTER_SET(mesh, &mesh_cmds, NULL,
		"Thread mesh with mDNS + messaging");

/* ── nn_proto_client handlers ─────────────────────────────────────── */

#include <node_mgr/field_relay.h>
#include <node_mgr/nn_proto_client.h>

void mdns_ot_log_h2d(const uint8_t *payload, size_t len, void *user)
{
	NN_OSAL_UNUSED(user);
	/* Phase 6 standard handler: hub-initiated FIELD_OP -> reply via
	 * D2H FIELD_REPLY.  field_relay returns true if it consumed the
	 * frame; otherwise we fall through to app-specific dispatch. */
	if (field_relay_try_handle_h2d(payload, len)) {
		return;
	}
	if (len < 2) {
		return;
	}
	uint16_t cmd = nn_osal_get_le16(payload);
	if ((cmd & 0xFFF0) == 0x0F70) {
		/* delivery probe (gateway / hub diagnostics): count silently --
		 * a log line here becomes a SIGNED D2H LOG_LINE (~1 s of ECDSA)
		 * and would perturb the very thing being measured */
		g_probe_rx[cmd & 0x0F]++;
		return;
	}
	NN_LOG_INF("H2D received: cmd=0x%04x len=%zu", cmd, len);
}

void mdns_ot_log_g2d(uint16_t cmd, const uint8_t *args, size_t args_len, void *user)
{
	NN_OSAL_UNUSED(user);
	/* DBG: at INF this fired every 5 s (gateway state ping) and each
	 * line became a SIGNED D2H LOG_LINE — ~1 s of ECDSA per 5 s of
	 * uptime, per device, as pure background load. */
	NN_LOG_DBG("G2D received: cmd=0x%04x args=%zu B", cmd, args_len);
}

/* nn_session Phase-1 on-target selftest: derive mirrored device/hub
 * sessions from the real static ECDH, prove seal→open round-trips both
 * directions with header-AAD, that tamper + replay are rejected, and
 * TIME the symmetric seal+open for the FIELD_REPLY-sized payload so we
 * can compare against the ~2.6-8 s asymmetric hot path. */
static int cmd_nn_crypto(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);

	uint8_t ecdh[32];
	int rv = hub_crypto_static_ecdh(ecdh);
	if (rv) {
		nn_osal_shell_error(sh, "static ECDH unavailable (rv=%d) — "
			"device must be provisioned (hub pub set)", rv);
		return rv;
	}

	/* Both salts fixed here so the test is deterministic; real sessions
	 * use random per-boot salts (Phase 2). */
	uint8_t dev_salt[8] = {1,2,3,4,5,6,7,8};
	uint8_t hub_salt[8] = {8,7,6,5,4,3,2,1};

	nn_session_t dev, hub;
	rv  = nn_session_derive(&dev, ecdh, dev_salt, hub_salt, true);
	rv |= nn_session_derive(&hub, ecdh, dev_salt, hub_salt, false);
	if (rv) { nn_osal_shell_error(sh, "derive failed"); return -EIO; }

	const uint8_t aad[10] = {0x4E,0x4E, 0,0, 0,0,0,0, 0,0};   /* mock hdr */
	uint8_t pt[155];
	for (size_t i = 0; i < sizeof pt; i++) pt[i] = (uint8_t)i;

	uint8_t sealed[8 + sizeof pt + 16];
	uint8_t opened[sizeof pt];
	size_t  slen = 0, olen = 0;

	/* device → hub */
	rv = nn_session_seal(&dev, aad, sizeof aad, pt, sizeof pt,
			     sealed, sizeof sealed, &slen);
	if (rv) { nn_osal_shell_error(sh, "seal d2h rv=%d", rv); return rv; }
	rv = nn_session_open(&hub, aad, sizeof aad, sealed, slen,
			     opened, sizeof opened, &olen);
	if (rv || olen != sizeof pt || memcmp(opened, pt, sizeof pt)) {
		nn_osal_shell_error(sh, "open d2h rv=%d len=%zu", rv, olen);
		return -EBADMSG;
	}
	nn_osal_shell_print(sh, "d2h round-trip OK (%zu B pt -> %zu B sealed)",
			    sizeof pt, slen);

	/* hub → device */
	rv = nn_session_seal(&hub, aad, sizeof aad, pt, sizeof pt,
			     sealed, sizeof sealed, &slen);
	rv |= nn_session_open(&dev, aad, sizeof aad, sealed, slen,
			      opened, sizeof opened, &olen);
	if (rv || memcmp(opened, pt, sizeof pt)) {
		nn_osal_shell_error(sh, "h2d round-trip FAILED rv=%d", rv);
		return -EBADMSG;
	}
	nn_osal_shell_print(sh, "h2d round-trip OK");

	/* tamper: flip a ciphertext byte -> must fail auth */
	rv = nn_session_seal(&dev, aad, sizeof aad, pt, sizeof pt,
			     sealed, sizeof sealed, &slen);
	sealed[10] ^= 0x01;
	rv = nn_session_open(&hub, aad, sizeof aad, sealed, slen,
			     opened, sizeof opened, &olen);
	nn_osal_shell_print(sh, "tamper rejected: %s (rv=%d)",
			    rv == -EBADMSG ? "yes" : "NO!", rv);

	/* replay: re-open the first good record -> must be rejected */
	rv = nn_session_seal(&dev, aad, sizeof aad, pt, sizeof pt,
			     sealed, sizeof sealed, &slen);
	nn_session_open(&hub, aad, sizeof aad, sealed, slen,
			opened, sizeof opened, &olen);          /* accept */
	rv = nn_session_open(&hub, aad, sizeof aad, sealed, slen,
			     opened, sizeof opened, &olen);      /* replay */
	nn_osal_shell_print(sh, "replay rejected: %s (rv=%d)",
			    rv == -EEXIST ? "yes" : "NO!", rv);

	/* timing: N seal+open pairs, report per-op microseconds */
	const int N = 50;
	uint32_t t0 = nn_osal_uptime_ms_32();
	for (int i = 0; i < N; i++) {
		nn_session_seal(&dev, aad, sizeof aad, pt, sizeof pt,
				sealed, sizeof sealed, &slen);
		nn_session_open(&hub, aad, sizeof aad, sealed, slen,
				opened, sizeof opened, &olen);
	}
	uint32_t dt = nn_osal_uptime_ms_32() - t0;
	nn_osal_shell_print(sh,
		"timing: %d seal+open pairs in %u ms = %u us/pair "
		"(vs ~2.6-8 s asymmetric)", N, dt, (dt * 1000u) / N);

	nn_session_free(&dev);
	nn_session_free(&hub);
	memset(ecdh, 0, sizeof ecdh);
	return 0;
}

static int cmd_nn_id(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	const uint8_t *id  = nn_proto_client_get_device_id();
	const uint8_t *pub = nn_proto_client_get_pubkey();
	if (!id || !pub) {
		nn_osal_shell_error(sh, "nn_proto_client not initialised");
		return -ENODEV;
	}
	nn_osal_shell_print(sh, "device_id  : %02x%02x%02x%02x%02x%02x%02x%02x",
		    id[0],id[1],id[2],id[3],id[4],id[5],id[6],id[7]);
	/* Hex bytes assembled into one line per key so we can use the
	 * \n-terminating nn_osal_shell_print (which mirrors all backends);
	 * avoids the printf-without-newline shell_fprintf primitive. */
	char p256_hex[65 * 2 + 1];
	for (int i = 0; i < 65; i++) {
		snprintf(p256_hex + i * 2, 3, "%02x", pub[i]);
	}
	nn_osal_shell_print(sh, "p256_pub   : %s", p256_hex);

	/* Phase 6: also expose the device's long-term X25519 pubkey so the
	 * hub can register it via the API without having to BLE-re-provision. */
	uint8_t x25519_pub[32];
	hub_crypto_get_device_x25519_pub(x25519_pub);
	char x25519_hex[32 * 2 + 1];
	for (int i = 0; i < 32; i++) {
		snprintf(x25519_hex + i * 2, 3, "%02x", x25519_pub[i]);
	}
	nn_osal_shell_print(sh, "x25519_pub : %s", x25519_hex);

	nn_osal_shell_print(sh, "gateway    : %s",
		    nn_proto_client_gateway_known() ? "known" : "(unknown — waiting for HELLO)");
	return 0;
}

static int cmd_nn_send_d2g(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	NN_OSAL_UNUSED(argc); NN_OSAL_UNUSED(argv);
	int rv = nn_proto_client_send_d2g(0x0001 /* HUB_STATUS_QUERY */, NULL, 0);
	nn_osal_shell_print(sh, "send_d2g rv=%d", rv);
	return rv;
}

static int cmd_nn_send_d2h(nn_osal_shell_ctx_t *sh, size_t argc, char **argv)
{
	const char *msg = (argc >= 2) ? argv[1] : "hello-from-device";
	int rv = nn_proto_client_send_d2h((const uint8_t *)msg, strlen(msg));
	nn_osal_shell_print(sh, "send_d2h(%s) rv=%d", msg, rv);
	return rv;
}

NN_OSAL_SHELL_SUBCMD_SET_CREATE(nn_subs,
	NN_OSAL_SHELL_CMD(id,       cmd_nn_id,
		"Print device_id + P-256 pubkey"),
	NN_OSAL_SHELL_CMD(send_d2g, cmd_nn_send_d2g,
		"Send D2G HUB_STATUS_QUERY"),
	NN_OSAL_SHELL_CMD(send_d2h, cmd_nn_send_d2h,
		"Send D2H with given payload"),
	NN_OSAL_SHELL_CMD(crypto,   cmd_nn_crypto,
		"nn_session symmetric-crypto selftest + timing"),
	NN_OSAL_SHELL_SUBCMD_SET_END
);
NN_OSAL_SHELL_CMD_REGISTER_SET(nn, &nn_subs, NULL,
		"nn_proto_client controls");

/* ── Phase 3 Layer B: actuator + sensor pump ─────────────────────────────
 *
 *   * "led" actuator → drives the on-board WS2812 (GPIO 8) green when
 *     value≥0.5, off when <0.5.  Wired via auto_engine_register_actuator_cb,
 *     so set_field("led", v) — whether from the CoAP /field handler, an
 *     auto_engine rule firing, or the shell — toggles the strip.
 *
 *   * Sensor pump → periodic worker that writes a simulated temperature
 *     into auto_engine.  Without this, "device read temperature" returns
 *     null because no code ever pushes a value.
 */

static void led_actuator_cb(const char *name, float value, void *user)
{
	NN_OSAL_UNUSED(name); NN_OSAL_UNUSED(user);
#if DT_NODE_EXISTS(DT_ALIAS(led_strip))
	const struct device *strip = DEVICE_DT_GET(DT_ALIAS(led_strip));
	if (!device_is_ready(strip)) {
		NN_LOG_WRN("led: strip not ready");
		return;
	}
	struct led_rgb pix = (value >= 0.5f)
		? (struct led_rgb){ .r = 0x00, .g = 0x40, .b = 0x00 }  /* on  */
		: (struct led_rgb){ .r = 0x00, .g = 0x00, .b = 0x00 }; /* off */
	(void)led_strip_update_rgb(strip, &pix, 1);
	NN_LOG_INF("led: actuator → %.1f", (double)value);
#else
	NN_LOG_INF("led: actuator → %.1f (no led-strip device — DT alias unset)",
		(double)value);
#endif
}

#define SENSOR_PUMP_INTERVAL_MS 5000

static void sensor_pump_work(struct k_work *work)
{
	struct k_work_delayable *dw = k_work_delayable_from_work(work);

	/* Simulated temperature: 22 + 5*sin(2π · t / 60s) — mimics a slow
	 * environmental drift, reads in the 17..27 °C range.  Real hardware
	 * would replace this with an ADC / I²C / 1-Wire read. */
	uint32_t now_ms = nn_osal_uptime_ms_32();
	float    t      = (float)(now_ms % 60000) / 60000.0f;  /* 0..1 */
	float    temp   = 22.0f + 5.0f * sinf(2.0f * 3.14159265f * t);
	auto_engine_set_field("temperature", temp);
	auto_engine_push_tick();   /* periodic snapshot of every field to the hub */

	/* Reschedule. */
	k_work_reschedule(dw, K_MSEC(SENSOR_PUMP_INTERVAL_MS));
}

static K_WORK_DELAYABLE_DEFINE(sensor_pump_dw, sensor_pump_work);

static void sensor_pump_start(void)
{
	k_work_reschedule(&sensor_pump_dw, K_MSEC(2000));
	NN_LOG_INF("sensor pump scheduled (every %d ms)",
		SENSOR_PUMP_INTERVAL_MS);
}

/* ── main ────────────────────────────────────────────────────────── */

#include <openthread/ip6.h>
#include <openthread/instance.h>
#if defined(CONFIG_OPENTHREAD_LINK_METRICS_MANAGER)
#include <openthread/link_metrics.h>
#endif

int main(void)
{
	printk("MAIN: entered\n");
	NN_LOG_INF("Thread mesh + mDNS node starting");
	/* Disable OT's IP6 receive filter so off-mesh / NAT64 replies
	 * destined to our OMR address aren't dropped before reaching
	 * Zephyr's L2 bridge.  Without this, `mesh ota check` hangs
	 * because the 141-byte CoAP reply from hub-via-NAT64 is filtered
	 * by OT and `ot_receive_handler` never sees it.
	 *
	 * Also turn on Thread 1.2 Link Metrics Manager.  Without it, route
	 * cost is driven only by MLE Advertisement (broadcast) reception —
	 * broadcasts are emitted at higher TX power than unicast on the
	 * ESP32-C6, so a router whose unicast path is broken (asymmetric
	 * antenna pattern, RX-only-broken peer) keeps a low broadcast LQI
	 * and stays on the routing table as a direct neighbor.  D2D
	 * AUTO_NOTIFY then goes out on the dead path indefinitely.
	 *
	 * Link Metrics Manager periodically queries each connected neighbor
	 * for the LQI/RSSI THEY see for us; that's true bidirectional
	 * quality, fed into the route cost calculation.  Once on, OT
	 * demotes asymmetric peers automatically within a couple of MLE
	 * intervals (60-120 s), and the cascade reaches them via the next
	 * best router. */
	{
		otInstance *inst = (otInstance *)nn_pal_ot_instance();
		if (inst) {
			otIp6SetReceiveFilterEnabled(inst, false);
			printk("ota: OT IP6 receive filter DISABLED\n");
#if defined(CONFIG_OPENTHREAD_LINK_METRICS_MANAGER)
			otLinkMetricsManagerSetEnabled(inst, true);
			printk("ot: Link Metrics Manager enabled\n");
#endif
		}
	}

	/*
	 * Load persisted device name from NVS.
	 * nn_osal_kv_load_all() triggers name_kv_load() if "mesh_app/name"
	 * was previously saved.  If not found, g_device_name stays at the
	 * zero-initialised empty string — we fall back to CONFIG_APP_DEVICE_NAME.
	 */
	nn_osal_kv_init();
	nn_osal_kv_register("mesh_app", name_kv_load, NULL);
	nn_osal_kv_load_all();

	/* Initialise hub crypto: load/generate device X25519 key pair. */
	int crypto_err = hub_crypto_init();
	if (crypto_err) {
		NN_LOG_ERR("hub_crypto_init failed: %d", crypto_err);
	}

	if (g_device_name[0] == '\0') {
		/* First boot — use Kconfig default */
		strncpy(g_device_name, CONFIG_APP_DEVICE_NAME,
			sizeof(g_device_name) - 1);
		NN_LOG_INF("No saved name — using default: %s", g_device_name);
	}

	/*
	 * Set mDNS hostname before the network stack processes events.
	 * The mDNS responder reads net_hostname_get() each time it answers
	 * a query, so setting it here is sufficient even though Thread
	 * isn't up yet.
	 */
	apply_device_name(g_device_name);

	/*
	 * nm_init() calls bt_enable() and blocks until Bluetooth is ready.
	 * The 802.15.4 radio is disabled inside nm_ble_acquire_rf() before
	 * any BLE scan, and re-enabled inside nm_thread_*() before Thread
	 * start — no manual coex management needed in main.
	 */
	int err = nm_init();
	if (err) {
		NN_LOG_ERR("nm_init failed: %d", err);
	}

	messenger_start();
	/* coap_info_start() removed — its only live function was the
	 * CoAP /auto receiver, now replaced by the D2D AUTO_NOTIFY handler
	 * registered inside auto_engine_init(). */

	/* Phase 3 nn_proto client (D2H/D2G ↔ G2D/H2D over UDP via gateway).
	 * Coexists with CoAP for now; Phase 5 deletes the CoAP path.  H2D
	 * delivery is logged for the Phase-3 e2e demo; richer dispatch
	 * (decrypt → automation engine, etc.) lands in Phase 4. */
	{
		extern void mdns_ot_log_h2d(const uint8_t *, size_t, void *);
		extern void mdns_ot_log_g2d(uint16_t, const uint8_t *, size_t, void *);
		struct nn_proto_client_config cli_cfg = {
			.on_h2d = mdns_ot_log_h2d,
			.on_g2d = mdns_ot_log_g2d,
		};
		int rv = nn_proto_client_init(&cli_cfg);
		if (rv) {
			NN_LOG_WRN("nn_proto_client_init: %d", rv);
		}
	}

	/* Phase 7: H2D INFO_QUERY handler replaces the old CoAP /info path. */
	{
		extern int info_handler_start(const char *device_name,
					      const char *image_name);
		int rv = info_handler_start(g_device_name, CONFIG_NODE_MGR_IMAGE_NAME);
		if (rv) {
			NN_LOG_WRN("info_handler_start: %d", rv);
		}
	}

	/* Phase 2 symmetric sessions: mint this boot's salt + register the
	 * SESS_INIT handler BEFORE the first INFO_REPLY carries the salt. */
	{
		int rv = nn_session_boot_init();
		if (rv) {
			NN_LOG_WRN("nn_session_boot_init: %d", rv);
		}
	}

	/* Phase 7: start D2H LOG_LINE backend (relies on nn_proto_client_init). */
	coap_log_start(NULL);

	printk("MAIN: ota_client_init() begin\n");
	ota_client_init();
	printk("MAIN: ota_client_init() done; ota_client_confirm() begin\n");
	{
		int cf_rc = ota_client_confirm();
		printk("MAIN: ota_client_confirm() rc=%d\n", cf_rc);
	}
	printk("MAIN: time_sync_init() begin\n");
	time_sync_init();
	printk("MAIN: time_sync_init() done\n");

	/* Register fields this device supports (reported in CoAP /info) */
	auto_engine_register_field("temperature", AUTO_FIELD_TYPE_SENSOR, -40, 85);
	auto_engine_register_field("humidity", AUTO_FIELD_TYPE_SENSOR, 0, 100);
	auto_engine_register_field("light", AUTO_FIELD_TYPE_SENSOR, 0, 1000);
	auto_engine_register_field("fan", AUTO_FIELD_TYPE_ACTUATOR, 0, 1);
	auto_engine_register_field("led", AUTO_FIELD_TYPE_ACTUATOR, 0, 1);
	auto_engine_init();

	/* Phase 7: H2D AUTO_PUSH handler accepts hub-pushed compiled
	 * automation blobs (replaces the legacy WS ConfigResponse path). */
	{
		extern int auto_push_handler_start(void);
		int rv = auto_push_handler_start();
		if (rv) {
			NN_LOG_WRN("auto_push_handler_start: %d", rv);
		}
	}

	/* H2D OTA_HINT handler: hub-initiated OTA (check + download + apply
	 * on a dedicated workqueue).  Must run after ota_client_init(). */
	printk("MAIN: ota_hint_handler_start begin\n");
	{
		extern int ota_hint_handler_start(void);
		int rv = ota_hint_handler_start();
		printk("MAIN: ota_hint_handler_start rc=%d\n", rv);
		if (rv) {
			NN_LOG_WRN("ota_hint_handler_start: %d", rv);
		}
	}

	/* H2D CLEAR_USER_DATA handler (device unregister): sealed command
	 * arms a clear-on-next-boot flag; the erase itself runs in
	 * clear_user_data_boot_check() before auto-attach. */
	{
		extern int clear_user_data_handler_start(void);
		int rv = clear_user_data_handler_start();
		if (rv) {
			NN_LOG_WRN("clear_user_data_handler_start: %d", rv);
		}
	}

	/* Phase 3 Layer B: hook actuator writes to the on-board WS2812 LED
	 * and start a periodic sensor pump.  See above for the cb/worker. */
	(void)auto_engine_register_actuator_cb("led", led_actuator_cb, NULL);
	sensor_pump_start();

#if defined(CONFIG_NODE_MGR_BUTTON_FLIP)
	(void)button_flip_init("button");
#elif defined(CONFIG_NODE_MGR_BUTTON_TOGGLE)
	(void)button_toggle_init("button");
#endif

	/* Explicit periodic D2H heartbeat so the hub's last_seen stays
	 * fresh independent of log-volume tuning. */
	{
		extern int heartbeat_start(void);
		int rv = heartbeat_start();
		if (rv) NN_LOG_WRN("heartbeat_start: %d", rv);
		/* cumulative radio/mesh counters to the hub every 5 min */
		extern int radio_stats_start(void);
		int rsv = radio_stats_start();
		if (rsv) NN_LOG_WRN("radio_stats_start: %d", rsv);
		/* answer the hub's channel-vote scan requests */
		extern int channel_scan_start(void);
		int csv = channel_scan_start();
		if (csv) NN_LOG_WRN("channel_scan_start: %d", csv);
	}

	printk("MAIN: about to print Ready — firmware: %s\n",
	       nn_osal_app_version());
	NN_LOG_INF("Ready — hostname: %s.local  firmware: %s",
		g_device_name, nn_osal_app_version());

	/* Leaf-node policy: these sensors never take the router role.
	 * The Zephyr C6 802.15.4 driver cannot generate enhanced ACKs
	 * (the console's "enh-ack generating handler" E-spam), and
	 * router↔router links lean on that machinery — measured ~50%
	 * H2D loss as routers vs 0% as children.  A 4-node mesh with an
	 * always-on NCP leader needs no sensor routers anyway.  Runtime
	 * flag, not persisted by OT → set every boot, before attach. */
	{
		otInstance *ot = (otInstance *)nn_pal_ot_instance();
		if (ot) {
			nn_pal_ot_mutex_lock();
			otThreadSetRouterEligible(ot, false);
			nn_pal_ot_mutex_unlock();
			printk("MAIN: router-eligible disabled (leaf-only)\n");
		}
	}

	/* Boot-time auto-attach: if the persisted prov_state says
	 * PROVISIONED *and* OT confirms the active dataset, bring Thread
	 * up immediately so an OTA-reboot or cold-cycle doesn't require a
	 * UART `ot ifconfig up + ot thread start`.  Falls back to printing
	 * the BLE provisioning hint otherwise. */
	{
		int rc = im_boot_auto_attach();
		if (rc == 0) {
			NN_LOG_INF("Thread auto-attaching — mesh status will "
				"show role within ~30 s");
			/* Registered: Bluetooth was never started (see nm_init);
			 * it comes up only for setup mode / provisioning. */
			NN_LOG_INF("registered: Bluetooth %s",
				   nn_pal_ble_is_ready() ? "ON (unexpected)" : "off");
		} else if (rc == -ENOENT) {
			/* Setup mode must be REACHABLE, not just announced: a
			 * just-unregistered (or factory-fresh) device has no
			 * console attached, so waiting for a manual
			 * `mesh start_joiner` strands it.  Advertise for BLE
			 * provisioning immediately and forever — the hub's
			 * add-device wizard can then claim it anytime.  The
			 * provisioning workers stop the advert on success. */
			NN_LOG_INF("Device unprovisioned — starting BLE "
				"provisioning advertising");
			nm_ble_acquire_rf();
			int prc = prov_peripheral_start();
			if (prc) {
				NN_LOG_WRN("prov_peripheral_start: %d — "
					"fall back to `mesh start_joiner`", prc);
			}
		} else {
			NN_LOG_WRN("im_boot_auto_attach: %d — falling back to "
				"manual shell start", rc);
		}
	}

	NN_LOG_INF("  mesh name <device1|device2|device3>  — set identity");
	NN_LOG_INF("  mesh start_leader / start_joiner / start_broker");
	NN_LOG_INF("  mesh send device2.local \"hello\"");
	NN_LOG_INF("  mesh status  |  mesh cache");
	printk("MAIN: returning 0\n");

	return 0;
}
