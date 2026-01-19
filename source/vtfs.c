#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/mount.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

#define MODULE_NAME "vtfs"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("VTFS: RAM-backed FS");
#define LOG(fmt, ...)  pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)

#define VTFS_VFS_ROOT_INO 100

struct vtfs_file_content {
    char *data;
    size_t size;
    size_t allocated;
};

struct vtfs_file_info {
    char name[256];
    ino_t ino;
    ino_t parent_ino;
    bool is_dir;

    struct list_head all_list;
    struct list_head sibling_list;
    struct list_head children;

    struct vtfs_file_content content;
    struct mutex lock;
};

struct vtfs_storage_ops {
    struct vtfs_file_info *(*find_by_ino)(ino_t ino);
    struct vtfs_file_info *(*find_in_dir)(ino_t parent_ino, const char *name);

    int (*create_file)(ino_t parent_ino, const char *name, ino_t *out_ino);
    int (*unlink_file)(ino_t parent_ino, const char *name);

    int (*mkdir)(ino_t parent_ino, const char *name, ino_t *out_ino);
    int (*rmdir)(ino_t parent_ino, const char *name);

    ssize_t (*read)(ino_t ino, char __user *buf, size_t len, loff_t *ppos);
    ssize_t (*write)(ino_t ino, const char __user *buf, size_t len, loff_t *ppos);

    int (*init_root)(ino_t root_ino);
    void (*destroy_all)(void);
};

static LIST_HEAD(vtfs_all_files);
static DEFINE_MUTEX(vtfs_files_lock);
static int vtfs_next_ino = 101;

static struct vtfs_file_info *ram_find_by_ino(ino_t ino)
{
    struct vtfs_file_info *fi;
    list_for_each_entry(fi, &vtfs_all_files, all_list) {
        if (fi->ino == ino)
            return fi;
    }
    return NULL;
}

static struct vtfs_file_info *ram_find_in_dir(ino_t parent_ino, const char *name)
{
    struct vtfs_file_info *parent, *fi;

    parent = ram_find_by_ino(parent_ino);
    if (!parent || !parent->is_dir)
        return NULL;

    list_for_each_entry(fi, &parent->children, sibling_list) {
        if (strcmp(fi->name, name) == 0)
            return fi;
    }
    return NULL;
}

static bool ram_dir_empty(struct vtfs_file_info *dir)
{
    return list_empty(&dir->children);
}

static int ram_init_root(ino_t root_ino)
{
    struct vtfs_file_info *root;

    mutex_lock(&vtfs_files_lock);

    if (ram_find_by_ino(root_ino)) {
        mutex_unlock(&vtfs_files_lock);
        return 0;
    }

    root = kzalloc(sizeof(*root), GFP_KERNEL);
    if (!root) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOMEM;
    }

    mutex_init(&root->lock);
    INIT_LIST_HEAD(&root->all_list);
    INIT_LIST_HEAD(&root->sibling_list);
    INIT_LIST_HEAD(&root->children);

    root->ino = root_ino;
    root->parent_ino = root_ino;
    root->is_dir = true;
    strscpy(root->name, "/", sizeof(root->name));

    list_add_tail(&root->all_list, &vtfs_all_files);

    if (vtfs_next_ino <= root_ino)
        vtfs_next_ino = root_ino + 1;

    mutex_unlock(&vtfs_files_lock);
    return 0;
}

static int ram_create_file(ino_t parent_ino, const char *name, ino_t *out_ino)
{
    struct vtfs_file_info *fi;
    struct vtfs_file_info *parent;

    mutex_lock(&vtfs_files_lock);

    parent = ram_find_by_ino(parent_ino);
    if (!parent || !parent->is_dir) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOTDIR;
    }

    if (ram_find_in_dir(parent_ino, name)) {
        mutex_unlock(&vtfs_files_lock);
        return -EEXIST;
    }

    fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOMEM;
    }

    mutex_init(&fi->lock);
    INIT_LIST_HEAD(&fi->all_list);
    INIT_LIST_HEAD(&fi->sibling_list);
    INIT_LIST_HEAD(&fi->children);

    fi->ino = vtfs_next_ino++;
    fi->parent_ino = parent_ino;
    fi->is_dir = false;
    strscpy(fi->name, name, sizeof(fi->name));

    list_add_tail(&fi->all_list, &vtfs_all_files);
    list_add_tail(&fi->sibling_list, &parent->children);

    mutex_unlock(&vtfs_files_lock);

    *out_ino = fi->ino;
    return 0;
}

static int ram_unlink_file(ino_t parent_ino, const char *name)
{
    struct vtfs_file_info *fi;
    struct vtfs_file_info *parent;

    mutex_lock(&vtfs_files_lock);

    parent = ram_find_by_ino(parent_ino);
    if (!parent || !parent->is_dir) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOTDIR;
    }

    fi = ram_find_in_dir(parent_ino, name);
    if (!fi) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOENT;
    }

    if (fi->is_dir) {
        mutex_unlock(&vtfs_files_lock);
        return -EISDIR;
    }

    mutex_lock(&fi->lock);
    kfree(fi->content.data);
    fi->content.data = NULL;
    fi->content.size = 0;
    fi->content.allocated = 0;
    mutex_unlock(&fi->lock);

    list_del(&fi->sibling_list);
    list_del(&fi->all_list);
    kfree(fi);

    mutex_unlock(&vtfs_files_lock);
    return 0;
}

static int ram_mkdir(ino_t parent_ino, const char *name, ino_t *out_ino)
{
    struct vtfs_file_info *fi;
    struct vtfs_file_info *parent;

    mutex_lock(&vtfs_files_lock);

    parent = ram_find_by_ino(parent_ino);
    if (!parent || !parent->is_dir) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOTDIR;
    }

    if (ram_find_in_dir(parent_ino, name)) {
        mutex_unlock(&vtfs_files_lock);
        return -EEXIST;
    }

    fi = kzalloc(sizeof(*fi), GFP_KERNEL);
    if (!fi) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOMEM;
    }

    mutex_init(&fi->lock);
    INIT_LIST_HEAD(&fi->all_list);
    INIT_LIST_HEAD(&fi->sibling_list);
    INIT_LIST_HEAD(&fi->children);

    fi->ino = vtfs_next_ino++;
    fi->parent_ino = parent_ino;
    fi->is_dir = true;
    strscpy(fi->name, name, sizeof(fi->name));

    list_add_tail(&fi->all_list, &vtfs_all_files);
    list_add_tail(&fi->sibling_list, &parent->children);

    mutex_unlock(&vtfs_files_lock);

    *out_ino = fi->ino;
    return 0;
}

static int ram_rmdir(ino_t parent_ino, const char *name)
{
    struct vtfs_file_info *fi;
    struct vtfs_file_info *parent;

    mutex_lock(&vtfs_files_lock);

    parent = ram_find_by_ino(parent_ino);
    if (!parent || !parent->is_dir) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOTDIR;
    }

    fi = ram_find_in_dir(parent_ino, name);
    if (!fi) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOENT;
    }

    if (!fi->is_dir) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOTDIR;
    }

    if (!ram_dir_empty(fi)) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOTEMPTY;
    }

    list_del(&fi->sibling_list);
    list_del(&fi->all_list);
    kfree(fi);

    mutex_unlock(&vtfs_files_lock);
    return 0;
}

static ssize_t ram_read(ino_t ino, char __user *buf, size_t len, loff_t *ppos)
{
    struct vtfs_file_info *fi;
    ssize_t ret;

    mutex_lock(&vtfs_files_lock);
    fi = ram_find_by_ino(ino);
    mutex_unlock(&vtfs_files_lock);

    if (!fi)
        return -ENOENT;
    if (fi->is_dir)
        return -EISDIR;

    mutex_lock(&fi->lock);

    if (*ppos >= fi->content.size) {
        ret = 0;
        goto out;
    }

    len = min(len, (size_t)(fi->content.size - *ppos));
    if (copy_to_user(buf, fi->content.data + *ppos, len)) {
        ret = -EFAULT;
        goto out;
    }

    *ppos += len;
    ret = len;

out:
    mutex_unlock(&fi->lock);
    return ret;
}

static ssize_t ram_write(ino_t ino, const char __user *buf, size_t len, loff_t *ppos)
{
    struct vtfs_file_info *fi;
    ssize_t ret = 0;
    char *tmp;

    mutex_lock(&vtfs_files_lock);
    fi = ram_find_by_ino(ino);
    mutex_unlock(&vtfs_files_lock);

    if (!fi)
        return -ENOENT;
    if (fi->is_dir)
        return -EISDIR;

    tmp = kmalloc(len, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;

    if (copy_from_user(tmp, buf, len)) {
        kfree(tmp);
        return -EFAULT;
    }

    mutex_lock(&fi->lock);

    if (*ppos + len > fi->content.allocated) {
        size_t new_size;
        char *new_data;

        new_size = max((size_t)(*ppos + len),
                       fi->content.allocated ? fi->content.allocated * 2 : (size_t)PAGE_SIZE);

        new_data = krealloc(fi->content.data, new_size, GFP_KERNEL);
        if (!new_data) {
            ret = -ENOMEM;
            goto out;
        }

        if (new_size > fi->content.allocated)
            memset(new_data + fi->content.allocated, 0, new_size - fi->content.allocated);

        fi->content.data = new_data;
        fi->content.allocated = new_size;
    }

    memcpy(fi->content.data + *ppos, tmp, len);
    *ppos += len;

    if (*ppos > fi->content.size)
        fi->content.size = *ppos;

    ret = (ssize_t)len;

out:
    mutex_unlock(&fi->lock);
    kfree(tmp);
    return ret;
}


static void ram_destroy_all(void)
{
    struct vtfs_file_info *fi, *tmp;

    mutex_lock(&vtfs_files_lock);

    list_for_each_entry_safe(fi, tmp, &vtfs_all_files, all_list) {
        mutex_lock(&fi->lock);
        kfree(fi->content.data);
        mutex_unlock(&fi->lock);

        list_del(&fi->all_list);
        if (!list_empty(&fi->sibling_list))
            list_del(&fi->sibling_list);
        kfree(fi);
    }

    mutex_unlock(&vtfs_files_lock);
}

static const struct vtfs_storage_ops ram_storage = {
    .find_by_ino = ram_find_by_ino,
    .find_in_dir = ram_find_in_dir,

    .create_file = ram_create_file,
    .unlink_file = ram_unlink_file,

    .mkdir       = ram_mkdir,
    .rmdir       = ram_rmdir,

    .read        = ram_read,
    .write       = ram_write,

    .init_root   = ram_init_root,
    .destroy_all = ram_destroy_all,
};

static const struct vtfs_storage_ops *st = &ram_storage;

static struct dentry *vtfs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags);
static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode,
                       struct dentry *child_dentry, umode_t mode, bool b);
static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);
static struct dentry *vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode,
                                 struct dentry *child_dentry, umode_t mode);
static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry);

static int vtfs_getattr(struct mnt_idmap *idmap,
                        const struct path *path,
                        struct kstat *stat,
                        u32 request_mask,
                        unsigned int flags)
{
    return simple_getattr(idmap, path, stat, request_mask, flags);
}

static const struct inode_operations vtfs_inode_ops = {
    .lookup  = vtfs_lookup,
    .create  = vtfs_create,
    .unlink  = vtfs_unlink,
    .mkdir   = vtfs_mkdir,
    .rmdir   = vtfs_rmdir,
    .getattr = vtfs_getattr,
};

static struct inode *vtfs_make_inode(struct super_block *sb, umode_t mode, ino_t ino, struct vtfs_file_info *fi)
{
    struct inode *inode = new_inode(sb);
    if (!inode)
        return NULL;

    inode->i_ino = ino;
    inode->i_mode = mode;
    inode->i_private = fi;

    i_uid_write(inode, 0);
    i_gid_write(inode, 0);

    inode_set_atime_to_ts(inode, current_time(inode));
    inode_set_mtime_to_ts(inode, current_time(inode));
    inode_set_ctime_to_ts(inode, current_time(inode));

    return inode;
}

static int vtfs_iterate(struct file *filp, struct dir_context *ctx)
{
    struct inode *inode = file_inode(filp);
    struct vtfs_file_info *dir_fi = inode->i_private;
    struct vtfs_file_info *fi;
    loff_t idx;

    if (!dir_fi || !dir_fi->is_dir)
        return -ENOTDIR;

    if (!dir_emit_dots(filp, ctx))
        return 0;

    idx = ctx->pos - 2;

    mutex_lock(&vtfs_files_lock);

    list_for_each_entry(fi, &dir_fi->children, sibling_list) {
        unsigned char type;
        size_t nlen;

        if (idx > 0) {
            idx--;
            continue;
        }

        type = fi->is_dir ? DT_DIR : DT_REG;
        nlen = strnlen(fi->name, sizeof(fi->name));

        if (!dir_emit(ctx, fi->name, nlen, fi->ino, type))
            break;

        ctx->pos++;
    }

    mutex_unlock(&vtfs_files_lock);
    return 0;
}

static ssize_t vtfs_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    return st->read(filp->f_inode->i_ino, buf, len, ppos);
}

static ssize_t vtfs_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
    struct inode *inode = filp->f_inode;
    struct vtfs_file_info *fi = inode->i_private;
    ssize_t ret;

    if (fi && (filp->f_flags & O_APPEND)) {
        mutex_lock(&fi->lock);
        *ppos = fi->content.size;
        mutex_unlock(&fi->lock);
    }

    ret = st->write(inode->i_ino, buf, len, ppos);

    if (ret > 0) {
        inode_set_mtime_to_ts(inode, current_time(inode));
        inode->i_size = max_t(loff_t, inode->i_size, *ppos);
    }

    return ret;
}


static int vtfs_open(struct inode *inode, struct file *filp)
{
    struct vtfs_file_info *fi = inode->i_private;

    if (!fi)
        return 0;

    if (fi->is_dir)
        return 0;

    if (filp->f_flags & O_TRUNC) {
        mutex_lock(&fi->lock);
        fi->content.size = 0;
        mutex_unlock(&fi->lock);

        inode->i_size = 0;
        inode_set_mtime_to_ts(inode, current_time(inode));
    }

    return 0;
}


static const struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
    .llseek         = generic_file_llseek,
};

static const struct file_operations vtfs_file_ops = {
    .open   = vtfs_open,
    .read   = vtfs_read,
    .write  = vtfs_write,
    .llseek = generic_file_llseek,
};

static struct dentry *vtfs_lookup(struct inode *parent_inode,
                                  struct dentry *child_dentry,
                                  unsigned int flags)
{
    struct vtfs_file_info *fi;
    struct inode *inode;

    (void)flags;

    if (child_dentry->d_name.len > NAME_MAX)
        return ERR_PTR(-ENAMETOOLONG);

    mutex_lock(&vtfs_files_lock);
    fi = st->find_in_dir(parent_inode->i_ino, child_dentry->d_name.name);
    mutex_unlock(&vtfs_files_lock);

    if (!fi) {
        d_add(child_dentry, NULL);
        return NULL;
    }

    inode = vtfs_make_inode(parent_inode->i_sb,
                            fi->is_dir ? (S_IFDIR | 0777) : (S_IFREG | 0666),
                            fi->ino, fi);
    if (!inode)
        return ERR_PTR(-ENOMEM);

    inode->i_op  = &vtfs_inode_ops;
    inode->i_fop = fi->is_dir ? &vtfs_dir_ops : &vtfs_file_ops;

    d_add(child_dentry, inode);
    return NULL;
}

static int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode,
                       struct dentry *child_dentry, umode_t mode, bool b)
{
    ino_t ino;
    int err;
    struct vtfs_file_info *fi;
    struct inode *inode;

    (void)idmap;
    (void)b;

    if (!S_ISREG(mode))
        return -EINVAL;

    err = st->create_file(parent_inode->i_ino, child_dentry->d_name.name, &ino);
    if (err)
        return err;

    mutex_lock(&vtfs_files_lock);
    fi = st->find_by_ino(ino);
    mutex_unlock(&vtfs_files_lock);

    inode = vtfs_make_inode(parent_inode->i_sb, S_IFREG | 0666, ino, fi);
    if (!inode)
        return -ENOMEM;

    inode->i_op  = &vtfs_inode_ops;
    inode->i_fop = &vtfs_file_ops;

    d_add(child_dentry, inode);
    return 0;
}

static int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry)
{
    return st->unlink_file(parent_inode->i_ino, child_dentry->d_name.name);
}

static struct dentry *vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode,
                                 struct dentry *child_dentry, umode_t mode)
{
    ino_t ino;
    int err;
    struct vtfs_file_info *fi;
    struct inode *inode;

    (void)idmap;
    (void)mode;

    err = st->mkdir(parent_inode->i_ino, child_dentry->d_name.name, &ino);
    if (err)
        return ERR_PTR(err);

    mutex_lock(&vtfs_files_lock);
    fi = st->find_by_ino(ino);
    mutex_unlock(&vtfs_files_lock);

    inode = vtfs_make_inode(parent_inode->i_sb, S_IFDIR | 0777, ino, fi);
    if (!inode)
        return ERR_PTR(-ENOMEM);

    inode->i_op  = &vtfs_inode_ops;
    inode->i_fop = &vtfs_dir_ops;

    d_add(child_dentry, inode);
    return NULL;
}

static int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry)
{
    return st->rmdir(parent_inode->i_ino, child_dentry->d_name.name);
}

static void vtfs_evict_inode(struct inode *inode)
{
    truncate_inode_pages_final(&inode->i_data);
    clear_inode(inode);
}

static const struct super_operations vtfs_super_ops = {
    .statfs      = simple_statfs,
    .evict_inode = vtfs_evict_inode,
};

static int vtfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct inode *root_inode;
    struct vtfs_file_info *root_fi;
    int err;

    (void)fc;

    sb->s_op = &vtfs_super_ops;

    err = st->init_root(VTFS_VFS_ROOT_INO);
    if (err)
        return err;

    mutex_lock(&vtfs_files_lock);
    root_fi = st->find_by_ino(VTFS_VFS_ROOT_INO);
    mutex_unlock(&vtfs_files_lock);

    root_inode = vtfs_make_inode(sb, S_IFDIR | 0777, VTFS_VFS_ROOT_INO, root_fi);
    if (!root_inode)
        return -ENOMEM;

    root_inode->i_op  = &vtfs_inode_ops;
    root_inode->i_fop = &vtfs_dir_ops;

    sb->s_root = d_make_root(root_inode);
    if (!sb->s_root)
        return -ENOMEM;

    return 0;
}

static int vtfs_get_tree(struct fs_context *fc)
{
    return get_tree_single(fc, vtfs_fill_super);
}

static int vtfs_init_fs_context(struct fs_context *fc)
{
    static const struct fs_context_operations ops = {
        .get_tree = vtfs_get_tree,
    };
    fc->ops = &ops;
    return 0;
}

static void vtfs_kill_sb(struct super_block *sb)
{
    st->destroy_all();
    kill_anon_super(sb);
}

static struct file_system_type vtfs_fs_type = {
    .owner           = THIS_MODULE,
    .name            = "vtfs",
    .init_fs_context = vtfs_init_fs_context,
    .kill_sb         = vtfs_kill_sb,
};

static int __init vtfs_init(void)
{
    int ret = register_filesystem(&vtfs_fs_type);
    if (ret == 0)
        LOG("VTFS joined the kernel\n");
    else
        LOG("Failed to register filesystem\n");
    return ret;
}

static void __exit vtfs_exit(void)
{
    unregister_filesystem(&vtfs_fs_type);
    LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);
