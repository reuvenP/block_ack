#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <net/ip.h>
#include <net/tcp.h>

MODULE_AUTHOR("Reuven Plevinsky");
MODULE_LICENSE("GPL");

#define USHORT_MAX 65535

static struct nf_hook_ops hook_ops;
static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;

u_int ack_seq = 0;
u_short sport = htons(80);

static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t port_display(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", ntohs(sport));
}

ssize_t port_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	u_int temp;
	if (sscanf(buf, "%u", &temp) == 1) {
		if (temp <= USHORT_MAX) {
			sport = htons(temp);
		}
	}
	return count;
}

ssize_t ack_display(struct device *dev, struct device_attribute *attr, char *buf)
{
        return scnprintf(buf, PAGE_SIZE, "%u\n", ntohl(ack_seq));
}

ssize_t ack_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        u_int temp;
        if (sscanf(buf, "%u", &temp) == 1) {
		ack_seq = htonl(temp);
        }
        return count;
}

static DEVICE_ATTR(port, S_IWUSR | S_IRUGO, port_display, port_modify);
static DEVICE_ATTR(ack, S_IWUSR | S_IRUGO, ack_display, ack_modify);

static unsigned int hfunc_out(void *priv,
			      struct sk_buff *skb,
			      const struct nf_hook_state *state)
{
	struct iphdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;

	if (!skb) {
		printk( KERN_ALERT "Error: SKB is null\n");
		return NF_ACCEPT;
	}

	ip_header = (struct iphdr *)skb_network_header(skb);
	if (!ip_header) {
		printk( KERN_ALERT "Error: iphdr is null\n");
		return NF_ACCEPT;
	}

	if (ip_header->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcp_header = (struct tcphdr *)(skb_transport_header(skb));
	if (!tcp_header) {
		printk( KERN_ALERT "Error: tcphdr is null\n");
		return NF_ACCEPT;
	}

	if ((ack_seq != 0) && (tcp_header->source == sport) && (tcp_header->ack_seq >= ack_seq)) {
		printk( KERN_ALERT "packet dropped. sport = %u, ack_seq = %u\n", ntohs(tcp_header->source), ntohl(tcp_header->ack_seq));
		return NF_DROP;
	}

        return NF_ACCEPT;
}

static int __init LKM_init(void)
{
	int status;
	hook_ops.hook = hfunc_out;
	hook_ops.hooknum = NF_INET_LOCAL_OUT;
	hook_ops.pf = PF_INET;
	hook_ops.priority = NF_IP_PRI_FIRST;
	
	status = nf_register_hook(&hook_ops);
	if (status != 0) {
		printk( KERN_ALERT "Error: failed to register the hook\n");
		return status;
	}

	major_number = register_chrdev(0, "Block_ACK", &fops);
	if (major_number < 0) {
		printk( KERN_ALERT "Error: failed to register chardev\n");
		status = -1;
		goto un_hook;
	}

	sysfs_class = class_create(THIS_MODULE, "Block_ACK_class");
	if (IS_ERR(sysfs_class)) {
		printk( KERN_ALERT "Error: failed to create class\n");
		status = -1;
		goto un_chardev;
	}
	
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "Block_ACK_class" "_" "Device");
	if (IS_ERR(sysfs_device)) {
		printk( KERN_ALERT "Error: failed to create device\n");
		status = -1;
		goto un_class;
	}

	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_port.attr)) {
		printk( KERN_ALERT "Error: failed to create file for port\n");
		status = -1;
		goto un_device;
	}

	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_ack.attr)) {
                printk( KERN_ALERT "Error: failed to create file for ack\n");
                status = -1;
                goto un_port_file;
        }

	return 0;

un_port_file:
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_port.attr);

un_device:
	device_destroy(sysfs_class, MKDEV(major_number, 0));

un_class:
	class_destroy(sysfs_class);

un_chardev:
	unregister_chrdev(major_number, "Block_ACK");
		
un_hook:
	nf_unregister_hook(&hook_ops);
	return status;
}

static void __exit LKM_exit(void)
{
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_ack.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_port.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "Block_ACK");
	nf_unregister_hook(&hook_ops);
}

module_init(LKM_init);
module_exit(LKM_exit);
















