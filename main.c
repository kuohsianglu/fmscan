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

static void fmscan_le_meta_evt(int len)
{
	int hdr_len = 1 + HCI_EVENT_HDR_SIZE;
	le_advertising_info *info;
	evt_le_meta_event *meta;
	char addr[ETH_ALEN * 3];
	struct fmscan_peer *peer;
	int offset = 0;
	char of_pubkey[60];
	int i;

	memset(of_pubkey, 0, sizeof(of_pubkey));

	meta = (void *)&buf[hdr_len];
	len -= hdr_len;

	if (meta->subevent != EVT_LE_ADVERTISING_REPORT)
		return;

	info = (le_advertising_info *)(meta->data + 1);

	if (!info->length)
		return;

	while (offset < info->length) {
		size_t len = info->data[offset];
		uint8_t eir_type = info->data[offset + 1];

		if (len + 1 > info->length)
			return;

		uint16_t com_id = info->data[offset + 2] | info->data[offset + 3];
		uint8_t maf_type = info->data[offset + 4];

		if (eir_type != EIR_MANUFACTURE_SPECIFIC || com_id != APPLE_COM_ID ||
			maf_type != OFFLINE_FINDING_TYPE || len != OFFLINE_FINDING_LEN)
			return;

		bdaddr_t addr_be;
		baswap(&addr_be, &info->bdaddr);

		uint8_t key_2bit = info->data[offset + 29] << 6;
		uint8_t key_6bit = addr_be.b[0] & 0x3f;
		addr_be.b[0] = key_2bit | key_6bit;

		for (i = 0; i < 6; i++)
			sprintf(&of_pubkey[i * 2], "%02x", addr_be.b[i]);

		for (i = 0; i < 22; i++)
			sprintf(&of_pubkey[i * 2 + 12], "%02x", info->data[offset + 7 + i]);

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

	if (info->bdaddr_type == LE_PUBLIC_ADDRESS)
		peer->public = 1;
	if (*of_pubkey)
		strcpy(peer->of_pub_key, of_pubkey);

	printf("* %s (%s)", peer->addr, peer->public ? "public" : "random");
	printf(" rssi = %d dBm ", peer->rssi);
	printf(" key = %s ", of_pubkey);

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

	avl_for_each_element_safe(&peer_tree, peer, avl, tmp) {
		if (ts.tv_sec - peer->ts.tv_sec < config.lescan_max_age) {
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
