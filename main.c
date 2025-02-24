#include "fmscan.h"

struct avl_tree peer_tree = AVL_TREE_INIT(peer_tree, avl_strcmp, false, NULL);
static unsigned char buf[HCI_MAX_FRAME_SIZE];
static struct uloop_timeout lescan_timer;
static struct uloop_timeout lescan_abort;

int hdev;
struct uloop_fd fd;
struct fmscan_config config = {
	.lescan_timeout = 15000,
	.lescan_max_age = 60,
};

static void fmscan_connect(struct fmscan_peer *peer)
{
	bdaddr_t bdaddr;
	uint16_t interval, latency, max_ce_length, max_interval, min_ce_length;
	uint16_t min_interval, supervision_timeout, window;
	uint8_t initiator_filter, own_bdaddr_type, peer_bdaddr_type;

	str2ba(peer->addr, &bdaddr);

	own_bdaddr_type = LE_PUBLIC_ADDRESS;
	if (peer->public)
		peer_bdaddr_type = LE_PUBLIC_ADDRESS;
	else
		peer_bdaddr_type = LE_RANDOM_ADDRESS;

	interval = htobs(0x0004);
	window = htobs(0x0004);
	initiator_filter = 0;
	min_interval = htobs(0x000F);
	max_interval = htobs(0x000F);
	latency = htobs(0x0000);
	supervision_timeout = htobs(0x0C80);
	min_ce_length = htobs(0x0000);
	max_ce_length = htobs(0x0000);

	if (hci_le_create_conn(fd.fd, interval, window, initiator_filter,
			       peer_bdaddr_type, bdaddr, own_bdaddr_type, min_interval,
			       max_interval, latency, supervision_timeout,
			       min_ce_length, max_ce_length, &peer->handle, 1000) < 0)
		fprintf(stderr, "%s:%s[%d]\n", __FILE__, __func__, __LINE__);
}

static void fmscan_le_meta_evt(int len)
{
	int hdr_len = 1 + HCI_EVENT_HDR_SIZE;
	le_advertising_info *info;
	evt_le_meta_event *meta;
	char addr[ETH_ALEN * 3];
	struct fmscan_peer *peer;
	uint8_t flags = 0;
	char name[256];
	char uuid128[33];
	char uuid16[5];
	int offset = 0;

	meta = (void *)&buf[hdr_len];
	len -= hdr_len;

	if (meta->subevent != EVT_LE_ADVERTISING_REPORT)
		return;
	info = (le_advertising_info *)(meta->data + 1);

	if (!info->length)
		return;

	memset(name, 0, sizeof(name));
	memset(uuid16, 0, sizeof(uuid16));
	memset(uuid128, 0, sizeof(uuid128));

	while (offset < info->length) {
		size_t len = info->data[offset];
		int i;

		if (len + 1 > info->length)
			return;

		switch(info->data[offset + 1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			memcpy(name, &info->data[offset + 2], len - 1);
			break;
		case EIR_FLAGS:
			flags = info->data[offset + 2];
			break;
		case EIR_UUID128_SOME:
			if (len - 1 != 16)
				continue;
			for (i = 0; i < 16; i++)
				sprintf(&uuid128[i * 2], "%02X", info->data[offset + 2 + i]);
			break;
		case EIR_UUID16_SOME:
			if (len - 1 != 2)
				continue;
			for (i = 0; i < 2; i++)
				sprintf(&uuid16[i * 2], "%02X", info->data[offset + 2 + i]);
			break;
		}
		offset += len + 1;
	}

	ba2str(&info->bdaddr, addr);
	peer = avl_find_element(&peer_tree, addr, peer, avl);
	if (!peer) {
		peer = malloc(sizeof(*peer));
		memset(peer, 0, sizeof(*peer));
		memcpy(peer->addr, addr, ETH_ALEN * 3);
		peer->avl.key = peer->addr;
		avl_insert(&peer_tree, &peer->avl);
	}
	peer->rssi = (int8_t)*(info->data + info->length);
	if (flags)
		peer->flags = flags;
	if (*name)
		strcpy(peer->name, name);
	if (*uuid16)
		strcpy(peer->uuid16, uuid16);
	if (*uuid128)
		strcpy(peer->uuid128, uuid128);
	if (info->bdaddr_type == LE_PUBLIC_ADDRESS)
		peer->public = 1;

	printf("* %s (%s)", peer->addr, peer->public ? "public" : "random");
	printf(" rssi = %d dBm ", peer->rssi);
	if (*peer->name)
		printf(" name = %s", peer->name);
	if (*peer->uuid16)
		printf(" uuid16 = 0x%s", peer->uuid16);
	if (*peer->uuid128)
		printf(" uuid128 = 0x%s", peer->uuid128);
	if (peer->flags)
		printf(" flags = 0x%08X", peer->flags);
	printf("\n");
	clock_gettime(CLOCK_MONOTONIC, &peer->ts);
}


static void fmscan_cb(struct uloop_fd *fd, unsigned int events)
{
	int len;

	memset(buf, 0, HCI_MAX_FRAME_SIZE);
	len = recv(fd->fd, buf, sizeof(buf), 0);

	switch (buf[1]) {
	case EVT_LE_META_EVENT:
		fmscan_le_meta_evt(len);
		break;
	}
}

static void fmscan_open(void)
{
	struct hci_filter filter;
	int ctl;

	hdev = hci_get_route(NULL);
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
	}
	ioctl(ctl, HCIDEVDOWN, hdev);
	ioctl(ctl, HCIDEVUP, hdev);

	fd.cb = fmscan_cb;
	fd.fd = hci_open_dev(hdev);
	if (fd.fd < 0) {
		ULOG_ERR("faile to open hci device\n");
		exit(1);
	}
	uloop_fd_add(&fd, ULOOP_READ);

	hci_filter_clear(&filter);
	hci_filter_all_ptypes(&filter);
	hci_filter_all_events(&filter);

	if (setsockopt(fd.fd, SOL_HCI, HCI_FILTER, &filter, sizeof(filter)) < 0)
		perror("setsockopt");
}

static void fmscan_con(void)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	struct fmscan_peer *peer;
	int i;

	cl = malloc(10 * sizeof(*ci) + sizeof(*cl));
	cl->dev_id = hdev;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(fd.fd, HCIGETCONNLIST, (void *) cl))
		return;

	avl_for_each_element(&peer_tree, peer, avl)
		peer->conn = 0;

	for (i = 0; i < cl->conn_num; i++, ci++) {
		char addr[18];
		char *str;

		ba2str(&ci->bdaddr, addr);
		str = hci_lmtostr(ci->link_mode);
		peer = avl_find_element(&peer_tree, addr, peer, avl);
		if (peer) {
			peer->conn = 1;
			peer->conn_type = ci->type;
			peer->conn_handle = ci->handle;
			peer->conn_state = ci->state;
		}

		bt_free(str);
	}

	free(cl);
}

static void fmscan_lescan(int enable)
{
	hci_le_set_scan_parameters(fd.fd, 1, 16, 16, 0, 0, 1000);
	hci_le_set_scan_enable(fd.fd, enable, 1, 1000);
}

static void fmscan_lescan_abort_cb(struct uloop_timeout *t)
{
	struct fmscan_peer *peer, *tmp;
	struct timespec ts;

	fprintf(stderr, "abort lescan\n");
	clock_gettime(CLOCK_MONOTONIC, &ts);

	fmscan_lescan(0);
	fmscan_con();

	avl_for_each_element_safe(&peer_tree, peer, avl, tmp) {
		if (peer->conn)
			continue;
		if (ts.tv_sec - peer->ts.tv_sec < config.lescan_max_age) {
			if (0 && !peer->handle)
				fmscan_connect(peer);
			continue;
		}
		avl_delete(&peer_tree, &peer->avl);
		free(peer);
	}

	if (config.lescan_timeout)
		uloop_timeout_set(&lescan_timer, config.lescan_timeout);
}

static void fmscan_lescan_timer_cb(struct uloop_timeout *t)
{
	fprintf(stderr, "start lescan\n");
	fmscan_lescan(1);

	uloop_timeout_set(&lescan_abort, 5000);
}

int main(int argc, char **argv)
{
	lescan_abort.cb = fmscan_lescan_abort_cb;
	lescan_timer.cb = fmscan_lescan_timer_cb;

	uloop_init();
	ubus_init();
	fmscan_open();
	uloop_timeout_set(&lescan_timer, 1000);
	uloop_run();
	uloop_done();

	return 0;
}
