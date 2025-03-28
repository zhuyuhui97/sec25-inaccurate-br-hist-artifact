#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/vmalloc.h>

MODULE_AUTHOR("ZHU Yuhui");
MODULE_LICENSE("GPL");

struct kobject bh_poc_kobj = {0};
void *exec_mem = NULL;
int train = 0;

static int alloc_rwx_mem(uint64_t size)
{
    // exec_mem is multiple pages
    exec_mem = vmalloc(size);
    if (!exec_mem)
    {
        printk(KERN_INFO "vmalloc failed\n");
        return -1;
    }
    return 0;
}

static void free_rwx_mem(void)
{
    if (exec_mem)
    {
        vfree(exec_mem);
        exec_mem = NULL;
    }
}

static ssize_t exec_mem_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "0x%llx\n", (unsigned long long)exec_mem);
}

static ssize_t exec_mem_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
    uint64_t req_size;
    sscanf(buf, "0x%llx", &req_size);
    if (req_size == 0){
        if (exec_mem)
        {
            free_rwx_mem();
        }
    }
    else{
        if (!exec_mem)
        {
            if (alloc_rwx_mem(req_size) < 0)
            {
                return -ENOMEM;
            }
        }
    }
    return count;
}

static void do_training(void)
{
    printk(KERN_INFO "Training...\n");
}

static ssize_t train_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    if (exec_mem)
    {
        do_training();
        return 0;
        // training code
    }
    else
    {
        printk(KERN_INFO "exec_mem is not allocated\n");
        return -EINVAL;
    }
}


static void mod_release(struct kobject *kobj)
{
    printk(KERN_INFO "bh_poc kobject release\n");
}

static struct kobj_attribute exec_mem_attribute = __ATTR_RW(exec_mem);
static struct kobj_attribute do_train_attribute = __ATTR_RO(train);

static struct attribute *exec_mem_attrs[] = {
    &exec_mem_attribute.attr,
    &do_train_attribute.attr,
    NULL,
};

ATTRIBUTE_GROUPS(exec_mem);

struct kobj_type bh_poc_ktype = {
    .sysfs_ops = &kobj_sysfs_ops,
    .default_groups = exec_mem_groups,
    .release = mod_release,
};

int __init mod_start(void)
{
    int retval;
    retval = kobject_init_and_add(&bh_poc_kobj, &bh_poc_ktype, NULL, "bh_poc");
    if (retval)
    {
        printk(KERN_INFO "kobject_init_and_add failed\n");
        return retval;
    }
    return 0;
}

void __exit mod_end(void)
{
    kobject_put(&bh_poc_kobj);
    printk(KERN_INFO "Goodbye Mr.\n");
}

module_init(mod_start);
module_exit(mod_end);