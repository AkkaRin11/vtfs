#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/printk.h>
#include <linux/string.h>

#define MODULE_NAME "vtfs"
#define VTFS_MAGIC  0x56544653

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("VTFS lab filesystem (part 4: lookup + dirs)");

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)

static struct inode *vtfs_get_inode(struct super_block *sb,
                                    const struct inode *dir,
                                    umode_t mode,
                                    ino_t ino);

/* ---------- iterate/readdir ---------- */

static int vtfs_iterate(struct file *filp, struct dir_context *ctx)
{
        struct dentry *dentry = filp->f_path.dentry;
        struct inode  *inode  = dentry->d_inode;

        if (ctx->pos == 0) {
                if (!dir_emit(ctx, ".", 1, inode->i_ino, DT_DIR))
                        return 0;
                ctx->pos++;
        }

        if (ctx->pos == 1) {
                ino_t pino = dentry->d_parent->d_inode->i_ino;
                if (!dir_emit(ctx, "..", 2, pino, DT_DIR))
                        return 0;
                ctx->pos++;
        }

        if (inode->i_ino == 100) {
                if (ctx->pos == 2) {
                        if (!dir_emit(ctx, "test.txt", 8, 101, DT_REG))
                                return 0;
                        ctx->pos++;
                }
                if (ctx->pos == 3) {
                        if (!dir_emit(ctx, "dir", 3, 200, DT_DIR))
                                return 0;
                        ctx->pos++;
                }
        }

        return 0;
}

static const struct file_operations vtfs_dir_ops = {
        .iterate_shared = vtfs_iterate,
        .llseek = generic_file_llseek,
        .read = generic_read_dir,
};

/* ---------- lookup ---------- */

static struct dentry *vtfs_lookup(struct inode *parent_inode,
                                  struct dentry *child_dentry,
                                  unsigned int flag)
{
        const char *name = child_dentry->d_name.name;
        ino_t pino = parent_inode->i_ino;
        struct inode *inode = NULL;

        if (pino == 100 && !strcmp(name, "test.txt")) {
                inode = vtfs_get_inode(parent_inode->i_sb, parent_inode,
                                       S_IFREG | 0777, 101);
        } else if (pino == 100 && !strcmp(name, "dir")) {
                inode = vtfs_get_inode(parent_inode->i_sb, parent_inode,
                                       S_IFDIR | 0777, 200);
        } else {
                inode = NULL; /* negative dentry */
        }

        d_add(child_dentry, inode);
        return NULL;
}

static const struct inode_operations vtfs_inode_ops = {
        .lookup = vtfs_lookup,
};

/* ---------- inode factory ---------- */

static struct inode *vtfs_get_inode(struct super_block *sb,
                                    const struct inode *dir,
                                    umode_t mode,
                                    ino_t ino)
{
        struct inode *inode = new_inode(sb);
        if (!inode)
                return NULL;

        inode_init_owner(&nop_mnt_idmap, inode, (struct inode *)dir, mode);
        inode->i_ino = ino;

        if (S_ISDIR(mode)) {
                inode->i_op  = &vtfs_inode_ops;
                inode->i_fop = &vtfs_dir_ops;
        } else if (S_ISREG(mode)) {
                /* На части 4 нам достаточно, чтобы inode существовал для stat/lookup. */
                inode->i_op  = NULL;
                inode->i_fop = NULL;
        }

        return inode;
}

/* ---------- superblock ---------- */

static int vtfs_fill_super(struct super_block *sb, void *data, int silent)
{
        struct inode *root_inode;

        LOG("fill_super called\n");

        sb->s_magic = VTFS_MAGIC;

        root_inode = vtfs_get_inode(sb, NULL, S_IFDIR | 0777, 100);
        if (!root_inode)
                return -ENOMEM;

        sb->s_root = d_make_root(root_inode);
        if (!sb->s_root)
                return -ENOMEM;

        LOG("superblock filled successfully\n");
        return 0;
}

/* ---------- fs_context / get_tree_single adapter ---------- */

static int vtfs_fill_super_fc(struct super_block *sb, struct fs_context *fc)
{
        return vtfs_fill_super(sb, fc->fs_private, 0);
}

static int vtfs_get_tree(struct fs_context *fc)
{
        return get_tree_single(fc, vtfs_fill_super_fc);
}

static int vtfs_init_fs_context(struct fs_context *fc)
{
        static const struct fs_context_operations vtfs_context_ops = {
                .get_tree = vtfs_get_tree,
        };

        fc->ops = &vtfs_context_ops;
        fc->fs_private = NULL;
        return 0;
}

/* ---------- filesystem_type + module init/exit ---------- */

static struct file_system_type vtfs_fs_type = {
        .owner = THIS_MODULE,
        .name = "vtfs",
        .init_fs_context = vtfs_init_fs_context,
        .kill_sb = kill_litter_super,
};

static int __init vtfs_init(void)
{
        int err;

        LOG("VTFS joined the kernel\n");
        err = register_filesystem(&vtfs_fs_type);
        if (err) {
                LOG("register_filesystem failed: %d\n", err);
                return err;
        }
        LOG("VTFS filesystem registered successfully\n");
        return 0;
}

static void __exit vtfs_exit(void)
{
        unregister_filesystem(&vtfs_fs_type);
        LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);
