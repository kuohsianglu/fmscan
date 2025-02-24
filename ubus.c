#include "fmscan.h"

static struct ubus_auto_conn ubus;
static struct blob_buf b;

static int ubus_device_cb(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct fmscan_peer *peer;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	blob_buf_init(&b, 0);

	avl_for_each_element(&peer_tree, peer, avl) {
		void *c;

		c = blobmsg_open_table(&b, peer->addr);
		blobmsg_add_u32(&b, "age", ts.tv_sec - peer->ts.tv_sec);
		blobmsg_add_u32(&b, "rssi", peer->rssi);
		if (peer->flags)
			blobmsg_add_u32(&b, "flags", peer->flags);
		if (*peer->name)
			blobmsg_add_string(&b, "name", peer->name);
		if (*peer->uuid16)
			blobmsg_add_string(&b, "uuid16", peer->uuid16);
		if (*peer->uuid128)
			blobmsg_add_string(&b, "uuid128", peer->uuid128);
		if (peer->conn) {
			blobmsg_add_u32(&b, "conn_handle", peer->conn_handle);
			blobmsg_add_u32(&b, "conn_state", peer->conn_state);
			blobmsg_add_u32(&b, "conn_type", peer->conn_type);
		}
		blobmsg_close_table(&b, c);
	}

	ubus_send_reply(ctx, req, b.head);

	return UBUS_STATUS_OK;
}

static const struct ubus_method fmscan_methods[] = {
	UBUS_METHOD_NOARG("devices", ubus_device_cb),
};

static struct ubus_object_type ubus_object_type =
	UBUS_OBJECT_TYPE("fmscan", fmscan_methods);

static struct ubus_object ubus_object = {
	.name = "fmscan",
	.type = &ubus_object_type,
	.methods = fmscan_methods,
	.n_methods = ARRAY_SIZE(fmscan_methods),
};

static void ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &ubus_object);
}

void ubus_init(void)
{
	ubus.cb = ubus_connect_handler;
        ubus_auto_connect(&ubus);
}
