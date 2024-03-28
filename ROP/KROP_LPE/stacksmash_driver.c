#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "stacksmash_device"
#define CLASS_NAME "stacksmash_driver_class"
#define MESSAGE_LEN 128

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keith Makan, Jack Ren");
MODULE_DESCRIPTION("A simple example of an ioctl based char driver");
MODULE_VERSION("0.01");

static int majorNumber;
static char *message;
static struct class *stacksmash_driver_class;
static struct device *stacksmash_driver_device;

static int stacksmash_dev_open(struct inode *, struct file *);
static int stacksmash_dev_release(struct inode *, struct file *);
static ssize_t stacksmash_dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t stacksmash_dev_write(struct file *, const char *, size_t, loff_t *);
static struct file_operations fops = {
        .open = stacksmash_dev_open,
        .read = stacksmash_dev_read,
        .write = stacksmash_dev_write,
        .release = stacksmash_dev_release,
};

static int __init stacksmash_driver_init(void) {
    printk(KERN_INFO "[stacksmash_driver] loaded! \n");
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0) {
        printk(KERN_ALERT "[stacksmash_driver] problem registering device...\n");
        return majorNumber;
    }
    printk(KERN_INFO "[stacksmash_driver] device registered successfully\n");
    stacksmash_driver_class = class_create(THIS_MODULE, CLASS_NAME);

    if (IS_ERR(stacksmash_driver_class)) {
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "[stacksmash_driver] failed to register device\n");
        return PTR_ERR(stacksmash_driver_class);
    }
    stacksmash_driver_device = device_create(stacksmash_driver_class, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(stacksmash_driver_device)) {
        class_destroy(stacksmash_driver_class);
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT  "[stacksmash_driver] failed to register device\n");
        return PTR_ERR(stacksmash_driver_class);
    }
    printk(KERN_INFO "[stacksmash_driver] device has been successfully created \n");
    message = (char *) kmalloc(sizeof(char) * MESSAGE_LEN, GFP_KERNEL);
    memset(message, 0, sizeof(char) * MESSAGE_LEN);

    return 0;
}

static void __exit stacksmash_driver_exit(void) {
    device_destroy(stacksmash_driver_class, MKDEV(majorNumber, 0));
    class_unregister(stacksmash_driver_class);
    class_destroy(stacksmash_driver_class);
    unregister_chrdev(majorNumber, DEVICE_NAME);
    kfree(message);
    printk(KERN_INFO "[stacksmash_driver] unloaded and device destroyed...\n");
}

static int stacksmash_dev_open(struct inode *inode, struct file *filep) {
    return 0;
}

static ssize_t stacksmash_dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int error_count = 0;
    error_count = copy_to_user(buffer, message, len < MESSAGE_LEN ? len : MESSAGE_LEN); //copy out of message into buffer

    if (error_count == 0) {
        printk(KERN_INFO "[stacksmash_driver] buffer copied to message holder\n");
        return len == 0;
    } else {
        printk(KERN_ALERT "[stacksmash_driver] buffer could not be copied\n");
        return -EFAULT;
    }

}

static ssize_t stacksmash_dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    char target_buf[8];
    char *local_buf = kmalloc(len, GFP_KERNEL);

    if (local_buf && copy_from_user(local_buf, buffer, len) == 0) {
        memcpy(target_buf, buffer, len); //no check to see if target_buf is big enough
        memcpy(message, buffer, len < MESSAGE_LEN ? len : MESSAGE_LEN);
        printk(KERN_INFO "[stacksmash_driver] message successfully copied message => [%s]", target_buf);
        kfree(local_buf);
        return strlen(message);
    } else {
        printk(KERN_ALERT "[stacksmash_driver] problem copying message...\n");
        return -EFAULT;
    }

}

static int stacksmash_dev_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "[stacksmash_driver] device released \n");
    return 0;
}

module_init(stacksmash_driver_init);
module_exit(stacksmash_driver_exit);
