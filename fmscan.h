#include <sys/types.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>

#include <linux/if_ether.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/ulog.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>

#define EIR_FLAGS			0x01
#define EIR_UUID16_SOME			0x02
#define EIR_UUID16_ALL			0x03
#define EIR_UUID32_SOME			0x04
#define EIR_UUID32_ALL			0x05
#define EIR_UUID128_SOME		0x06
#define EIR_UUID128_ALL			0x07
#define EIR_NAME_SHORT			0x08
#define EIR_NAME_COMPLETE		0x09
#define EIR_TX_POWER			0x0A
#define EIR_DEVICE_ID			0x10
#define EIR_MANUFACTURE_SPECIFIC	0xFF

#define APPLE_COM_ID			0x004c
#define OFFLINE_FINDING_TYPE		0x12
#define OFFLINE_FINDING_LEN		30

struct fmscan_config {
	int lescan_timeout;
	int lescan_max_age;
};

struct fmscan_peer {
	struct avl_node avl;

	char addr[ETH_ALEN * 3];
	int8_t rssi;
	int public;
	uint16_t handle;
	struct timespec ts;

	char of_pub_key[64];
};

extern struct uloop_fd fd;
extern struct fmscan_config config;
extern struct avl_tree peer_tree;
extern int hdev;

void ubus_init(void);

