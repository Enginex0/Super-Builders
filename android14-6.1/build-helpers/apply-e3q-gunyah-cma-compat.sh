#!/usr/bin/env bash
set -euo pipefail

KERNEL_TREE="${1:?usage: apply-e3q-gunyah-cma-compat.sh <kernel-tree>}"
GUNYAH_DIR="$KERNEL_TREE/drivers/virt/gunyah"
MAKEFILE="$GUNYAH_DIR/Makefile"
VM_MGR="$GUNYAH_DIR/vm_mgr.c"
VM_HDR="$GUNYAH_DIR/vm_mgr.h"
UAPI="$KERNEL_TREE/include/uapi/linux/gunyah.h"
BACKING_SRC="$GUNYAH_DIR/cma_compat.c"

for f in "$MAKEFILE" "$VM_MGR" "$VM_HDR" "$UAPI"; do
  test -f "$f" || { echo "FATAL: required Gunyah source missing: $f" >&2; exit 1; }
done

cat > "$BACKING_SRC" <<'EOF'
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Samsung e3q / Android 14-6.1 Gunyah bounded-extent userspace backing.
 *
 * Keep every physical run at least order-3 (8 pages / 32 KiB), so a 256 MiB
 * guest has at most 8192 runs. Prefer cheap buddy allocations. If fragmentation
 * prevents even an order-3 buddy allocation, use alloc_contig_pages(), which is
 * specifically intended for contiguous requests the buddy allocator cannot
 * satisfy and may migrate movable pages internally. The existing Samsung
 * GH_VM_SET_USER_MEM_REGION -> pin_user_pages() path remains unchanged.
 */
#define pr_fmt(fmt) "gh_extent_compat: " fmt

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/numa.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <uapi/linux/gunyah.h>

#define GH_EXTENT_MIN_ORDER 3U
#define GH_EXTENT_MAX_ORDER 6U
#define GH_EXTENT_MIN_PAGES (1UL << GH_EXTENT_MIN_ORDER)
#define GH_EXTENT_LIMIT 8192UL

struct gh_extent_chunk {
	struct page *base;
	unsigned int order;
	bool contig;
};

struct gh_extent_buffer {
	struct page **pages;
	struct gh_extent_chunk *chunks;
	unsigned long nr_pages;
	unsigned long nr_chunks;
	unsigned long chunk_capacity;
	unsigned long buddy_chunks;
	unsigned long contig_chunks;
	u64 size;
};

static void gh_extent_free_one(struct gh_extent_chunk *chunk)
{
	unsigned long nr_pages;

	if (!chunk || !chunk->base)
		return;

	nr_pages = 1UL << chunk->order;
	if (chunk->contig)
		free_contig_range(page_to_pfn(chunk->base), nr_pages);
	else
		__free_pages(chunk->base, chunk->order);

	chunk->base = NULL;
}

static void gh_extent_free_chunks(struct gh_extent_buffer *buf)
{
	unsigned long i;

	if (!buf)
		return;

	for (i = 0; i < buf->nr_chunks; i++)
		gh_extent_free_one(&buf->chunks[i]);
	buf->nr_chunks = 0;
}

static void gh_extent_destroy(struct gh_extent_buffer *buf)
{
	if (!buf)
		return;
	gh_extent_free_chunks(buf);
	kvfree(buf->chunks);
	kvfree(buf->pages);
	kfree(buf);
}

static struct page *gh_extent_alloc_buddy(unsigned long remaining,
					 unsigned int *order)
{
	const gfp_t gfp = GFP_HIGHUSER_MOVABLE | __GFP_ZERO | __GFP_COMP |
			  __GFP_NOWARN | __GFP_RETRY_MAYFAIL;
	unsigned int try_order = GH_EXTENT_MAX_ORDER;
	struct page *base;

	while ((1UL << try_order) > remaining && try_order > GH_EXTENT_MIN_ORDER)
		try_order--;

	for (;;) {
		base = alloc_pages(gfp, try_order);
		if (base) {
			*order = try_order;
			return base;
		}
		if (try_order == GH_EXTENT_MIN_ORDER)
			return NULL;
		try_order--;
	}
}

static struct page *gh_extent_alloc_contig(unsigned long remaining,
					  unsigned int *order)
{
#ifdef CONFIG_CONTIG_ALLOC
	/* alloc_contig_pages() must receive a non-__GFP_COMP mask. */
	const gfp_t gfp = GFP_HIGHUSER_MOVABLE | __GFP_NOWARN |
			  __GFP_RETRY_MAYFAIL;
	unsigned int try_order = GH_EXTENT_MAX_ORDER;
	struct page *base;
	unsigned long i;

	while ((1UL << try_order) > remaining && try_order > GH_EXTENT_MIN_ORDER)
		try_order--;

	for (;;) {
		base = alloc_contig_pages(1UL << try_order, gfp, NUMA_NO_NODE, NULL);
		if (base) {
			/* alloc_contig_pages() does not promise zero-filled target pages. */
			for (i = 0; i < (1UL << try_order); i++)
				clear_highpage(nth_page(base, i));
			*order = try_order;
			return base;
		}
		if (try_order == GH_EXTENT_MIN_ORDER)
			return NULL;
		try_order--;
	}
#else
	return NULL;
#endif
}

static int gh_extent_allocate(struct gh_extent_buffer *buf)
{
	unsigned long page_index = 0;
	unsigned long remaining = buf->nr_pages;
	bool logged_contig_fallback = false;

	while (remaining) {
		struct page *base;
		unsigned long chunk_pages;
		unsigned long i;
		unsigned int order = GH_EXTENT_MIN_ORDER;
		bool contig = false;

		base = gh_extent_alloc_buddy(remaining, &order);
		if (!base) {
			if (!logged_contig_fallback) {
				pr_info("buddy exhausted; enabling alloc_contig_pages fallback remaining_pages=%lu chunks=%lu\n",
					remaining, buf->nr_chunks);
				logged_contig_fallback = true;
			}
			base = gh_extent_alloc_contig(remaining, &order);
			contig = base != NULL;
		}

		if (!base) {
			pr_err("allocation failed remaining_pages=%lu chunks=%lu buddy=%lu contig=%lu min_order=%u\n",
			       remaining, buf->nr_chunks, buf->buddy_chunks,
			       buf->contig_chunks, GH_EXTENT_MIN_ORDER);
			return -ENOMEM;
		}

		if (buf->nr_chunks >= buf->chunk_capacity ||
		    buf->nr_chunks >= GH_EXTENT_LIMIT) {
			struct gh_extent_chunk temporary = {
				.base = base,
				.order = order,
				.contig = contig,
			};
			gh_extent_free_one(&temporary);
			pr_err("extent limit exceeded chunks=%lu capacity=%lu limit=%lu\n",
			       buf->nr_chunks, buf->chunk_capacity, GH_EXTENT_LIMIT);
			return -E2BIG;
		}

		chunk_pages = 1UL << order;
		buf->chunks[buf->nr_chunks].base = base;
		buf->chunks[buf->nr_chunks].order = order;
		buf->chunks[buf->nr_chunks].contig = contig;
		buf->nr_chunks++;
		if (contig)
			buf->contig_chunks++;
		else
			buf->buddy_chunks++;

		for (i = 0; i < chunk_pages; i++)
			buf->pages[page_index + i] = nth_page(base, i);

		page_index += chunk_pages;
		remaining -= chunk_pages;
		cond_resched();
	}

	if (page_index != buf->nr_pages)
		return -EFAULT;

	pr_info("allocated bounded backing pages=%lu chunks=%lu buddy=%lu contig=%lu max_extents=%lu min_order=%u max_order=%u\n",
		buf->nr_pages, buf->nr_chunks, buf->buddy_chunks,
		buf->contig_chunks, GH_EXTENT_LIMIT,
		GH_EXTENT_MIN_ORDER, GH_EXTENT_MAX_ORDER);
	return 0;
}

static int gh_extent_release(struct inode *inode, struct file *file)
{
	struct gh_extent_buffer *buf = file->private_data;

	if (buf)
		pr_info("released bounded backing pages=%lu chunks=%lu buddy=%lu contig=%lu bytes=%llu\n",
			buf->nr_pages, buf->nr_chunks, buf->buddy_chunks,
			buf->contig_chunks, (unsigned long long)buf->size);
	gh_extent_destroy(buf);
	return 0;
}

static int gh_extent_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct gh_extent_buffer *buf = file->private_data;
	unsigned long len = vma->vm_end - vma->vm_start;
	unsigned long nr_pages = PAGE_ALIGN(len) >> PAGE_SHIFT;
	int ret;

	if (!buf || !buf->pages)
		return -EINVAL;
	if (vma->vm_pgoff != 0)
		return -EINVAL;
	if (!len || len > buf->size || nr_pages > buf->nr_pages)
		return -EINVAL;

	file_accessed(file);
	ret = vm_map_pages_zero(vma, buf->pages, nr_pages);
	if (ret)
		pr_err("mmap failed pages=%lu chunks=%lu ret=%d\n",
		       nr_pages, buf->nr_chunks, ret);
	else
		pr_info("mapped bounded backing pages=%lu chunks=%lu buddy=%lu contig=%lu bytes=%lu\n",
			nr_pages, buf->nr_chunks, buf->buddy_chunks,
			buf->contig_chunks, len);
	return ret;
}

static const struct file_operations gh_extent_fops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.mmap = gh_extent_mmap,
	.release = gh_extent_release,
};

long gh_cma_compat_create_mem_fd(unsigned long arg)
{
	struct gh_extent_buffer *buf;
	struct file *file;
	u64 size;
	unsigned long nr_pages;
	int ret;
	int fd;

	if (copy_from_user(&size, (void __user *)arg, sizeof(size)))
		return -EFAULT;
	if (!size || !PAGE_ALIGNED(size) || size > SZ_512M)
		return -EINVAL;

	nr_pages = (unsigned long)(size >> PAGE_SHIFT);
	if (!nr_pages || (nr_pages % GH_EXTENT_MIN_PAGES) != 0)
		return -EINVAL;
	if (DIV_ROUND_UP(nr_pages, GH_EXTENT_MIN_PAGES) > GH_EXTENT_LIMIT)
		return -E2BIG;

	buf = kzalloc(sizeof(*buf), GFP_KERNEL_ACCOUNT);
	if (!buf)
		return -ENOMEM;

	buf->size = size;
	buf->nr_pages = nr_pages;
	buf->chunk_capacity = DIV_ROUND_UP(nr_pages, GH_EXTENT_MIN_PAGES);
	buf->pages = kvmalloc_array(nr_pages, sizeof(*buf->pages), GFP_KERNEL_ACCOUNT);
	buf->chunks = kvcalloc(buf->chunk_capacity, sizeof(*buf->chunks),
			       GFP_KERNEL_ACCOUNT);
	if (!buf->pages || !buf->chunks) {
		ret = -ENOMEM;
		goto err_destroy;
	}

	ret = gh_extent_allocate(buf);
	if (ret)
		goto err_destroy;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto err_destroy;
	}

	file = anon_inode_getfile("[gunyah-bounded-extents]", &gh_extent_fops,
				  buf, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		put_unused_fd(fd);
		goto err_destroy;
	}

	fd_install(fd, file);
	pr_info("allocated fd=%d pages=%lu chunks=%lu buddy=%lu contig=%lu bytes=%llu\n",
		fd, nr_pages, buf->nr_chunks, buf->buddy_chunks,
		buf->contig_chunks, (unsigned long long)size);
	return fd;

err_destroy:
	gh_extent_destroy(buf);
	return ret;
}
EOF

python3 - "$MAKEFILE" "$VM_HDR" "$VM_MGR" "$UAPI" <<'PY'
from pathlib import Path
import re
import sys

makefile, hdr, vm, uapi = map(Path, sys.argv[1:])

text = makefile.read_text()
if "cma_compat.o" not in text:
    lines = text.splitlines(keepends=True)
    candidates = [
        i for i, line in enumerate(lines)
        if re.match(r"^\s*gunyah-y\s*\+=", line) and "vm_mgr_mm.o" in line
    ]
    if len(candidates) != 1:
        raise SystemExit(
            f"FATAL: expected one Gunyah composite-object line containing vm_mgr_mm.o, found {len(candidates)}"
        )
    i = candidates[0]
    newline = "\n" if lines[i].endswith("\n") else ""
    lines[i] = lines[i].rstrip("\n").rstrip() + " cma_compat.o" + newline
    text = "".join(lines)
makefile.write_text(text)

text = hdr.read_text()
proto = "long gh_cma_compat_create_mem_fd(unsigned long arg);"
if proto not in text:
    pat = re.compile(
        r"(?m)^(?P<decl>\s*long\s+gh_dev_vm_mgr_ioctl\s*\(\s*struct\s+gh_rm\s*\*\s*rm\s*,\s*"
        r"unsigned\s+int\s+cmd\s*,\s*unsigned\s+long\s+arg\s*\)\s*;\s*)$"
    )
    matches = list(pat.finditer(text))
    if len(matches) != 1:
        raise SystemExit(
            f"FATAL: expected one gh_dev_vm_mgr_ioctl declaration, found {len(matches)}"
        )
    m = matches[0]
    text = text[:m.start()] + m.group("decl").rstrip() + "\n" + proto + text[m.end():]
hdr.write_text(text)

text = uapi.read_text()
macro = "GH_ANDROID_CREATE_CMA_COMPAT_MEM_FD"
if macro not in text:
    pat = re.compile(r"(?m)^\s*#\s*define\s+GH_ANDROID_IOCTL_TYPE\s+'A'\s*$")
    matches = list(pat.finditer(text))
    if len(matches) != 1:
        raise SystemExit(
            f"FATAL: expected one GH_ANDROID_IOCTL_TYPE 'A' definition, found {len(matches)}"
        )
    m = matches[0]
    addition = (
        m.group(0)
        + "\n\n/* e3q bounded-extent userspace RAM compatibility ABI. */\n"
        + "#define GH_ANDROID_CREATE_CMA_COMPAT_MEM_FD \\\n"
        + "\t_IOW(GH_ANDROID_IOCTL_TYPE, 0x20, __u64)"
    )
    text = text[:m.start()] + addition + text[m.end():]
uapi.write_text(text)

text = vm.read_text()
case = "case GH_ANDROID_CREATE_CMA_COMPAT_MEM_FD:"
if case not in text:
    pat = re.compile(
        r"long\s+gh_dev_vm_mgr_ioctl\s*\(\s*struct\s+gh_rm\s*\*\s*rm\s*,\s*"
        r"unsigned\s+int\s+cmd\s*,\s*unsigned\s+long\s+arg\s*\)\s*\{",
        re.MULTILINE,
    )
    matches = list(pat.finditer(text))
    if len(matches) != 1:
        raise SystemExit(
            f"FATAL: expected one gh_dev_vm_mgr_ioctl definition, found {len(matches)}"
        )
    start = matches[0].end()
    switch = re.search(r"\bswitch\s*\(\s*cmd\s*\)\s*\{", text[start:])
    if not switch:
        raise SystemExit("FATAL: gh_dev_vm_mgr_ioctl switch(cmd) not found")
    switch_end = start + switch.end()
    text = text[:switch_end] + (
        "\n\tcase GH_ANDROID_CREATE_CMA_COMPAT_MEM_FD:\n"
        "\t\treturn gh_cma_compat_create_mem_fd(arg);"
    ) + text[switch_end:]
vm.write_text(text)
PY

# Fail closed before invoking the kernel build.
grep -qF 'cma_compat.o' "$MAKEFILE"
grep -qF 'long gh_cma_compat_create_mem_fd(unsigned long arg);' "$VM_HDR"
grep -qF 'GH_ANDROID_CREATE_CMA_COMPAT_MEM_FD' "$UAPI"
grep -qF '_IOW(GH_ANDROID_IOCTL_TYPE, 0x20, __u64)' "$UAPI"
grep -qF 'case GH_ANDROID_CREATE_CMA_COMPAT_MEM_FD:' "$VM_MGR"
grep -qF '#define GH_EXTENT_MIN_ORDER 3U' "$BACKING_SRC"
grep -qF '#define GH_EXTENT_LIMIT 8192UL' "$BACKING_SRC"
grep -qF '__GFP_COMP' "$BACKING_SRC"
grep -qF 'alloc_pages(gfp, try_order)' "$BACKING_SRC"
grep -qF 'alloc_contig_pages(1UL << try_order, gfp, NUMA_NO_NODE, NULL)' "$BACKING_SRC"
grep -qF 'free_contig_range(page_to_pfn(chunk->base), nr_pages)' "$BACKING_SRC"
grep -qF 'clear_highpage(nth_page(base, i))' "$BACKING_SRC"
grep -qF 'cond_resched();' "$BACKING_SRC"
grep -qF 'vm_map_pages_zero(vma, buf->pages, nr_pages)' "$BACKING_SRC"
grep -qF '__free_pages(chunk->base, chunk->order)' "$BACKING_SRC"

# Never relax the Gunyah memory parcel safety guard as part of this fix.
grep -qF 'mapping->parcel.n_mem_entries > 8192' "$VM_MGR"
grep -qF 'ret = -E2BIG;' "$VM_MGR"

echo 'e3q Gunyah bounded backing verified: buddy + alloc_contig_pages fallback, min order=3, max 8192 extents, normal GUP path retained'
