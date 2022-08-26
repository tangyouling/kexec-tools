/*
 * kexec-loongarch.c - kexec for loongarch
 *
 * Copyright (C) 2022 Loongson Technology Corporation Limited.
 *   Youling Tang <tangyouling@loongson.cn>
 *
 * derived from kexec-arm64.c
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libfdt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/elf-em.h>
#include <elf.h>
#include <elf_info.h>

#include "kexec.h"
#include "kexec-loongarch.h"
#include "crashdump-loongarch.h"
#include "dt-ops.h"
#include "iomem.h"
#include "kexec-syscall.h"
#include "mem_regions.h"
#include "arch/options.h"

#define ROOT_NODE_ADDR_CELLS_DEFAULT 1
#define ROOT_NODE_SIZE_CELLS_DEFAULT 1

#define PROP_ADDR_CELLS "#address-cells"
#define PROP_SIZE_CELLS "#size-cells"
#define PROP_ELFCOREHDR "linux,elfcorehdr"
#define PROP_USABLE_MEM_RANGE "linux,usable-memory-range"

/* Return a sorted list of memory ranges. */
static struct memory_range memory_range[MAX_MEMORY_RANGES];

int get_memory_ranges(struct memory_range **range, int *ranges,
		      unsigned long UNUSED(kexec_flags))
{
	int memory_ranges = 0;

	const char *iomem = proc_iomem();
	char line[MAX_LINE];
	FILE *fp;
	unsigned long long start, end;
	char *str;
	int type, consumed, count;

	fp = fopen(iomem, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s: %s\n", iomem, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != 0) {
		if (memory_ranges >= MAX_MEMORY_RANGES)
			break;
		count = sscanf(line, "%llx-%llx : %n", &start, &end, &consumed);
		if (count != 2)
			continue;
		str = line + consumed;
		end = end + 1;
		if (!strncmp(str, SYSTEM_RAM, strlen(SYSTEM_RAM)))
			type = RANGE_RAM;
		else if(!strncmp(str, IOMEM_RESERVED, strlen(IOMEM_RESERVED)))
			type = RANGE_RESERVED;
		else
			continue;

		if (memory_ranges > 0 &&
		    memory_range[memory_ranges - 1].end == start &&
		    memory_range[memory_ranges - 1].type == type) {
			memory_range[memory_ranges - 1].end = end;
		} else {
			memory_range[memory_ranges].start = start;
			memory_range[memory_ranges].end = end;
			memory_range[memory_ranges].type = type;
			memory_ranges++;
		}
	}
	fclose(fp);
	*range = memory_range;
	*ranges = memory_ranges;

	dbgprint_mem_range("MEMORY RANGES:", *range, *ranges);
	return 0;
}

struct file_type file_type[] = {
	{"elf-loongarch", elf_loongarch_probe, elf_loongarch_load, elf_loongarch_usage},
	{"pei-loongarch", pei_loongarch_probe, pei_loongarch_load, pei_loongarch_usage},
};
int file_types = sizeof(file_type) / sizeof(file_type[0]);

/* loongarch global varables. */

struct loongarch_mem loongarch_mem = {
	.phys_offset = loongarch_mem_ngv,
};

/**
 * loongarch_process_image_header - Process the loongarch image header.
 */

int loongarch_process_image_header(const struct loongarch_image_header *h)
{

	if (!loongarch_header_check_pe_sig(h))
		return EFAILED;

	if (h->image_size) {
		loongarch_mem.text_offset = loongarch_header_text_offset(h);
		loongarch_mem.image_size = loongarch_header_image_size(h);
	}

	return 0;
}

void arch_usage(void)
{
	printf(loongarch_opts_usage);
}

struct arch_options_t arch_options = {
	.core_header_type = CORE_TYPE_ELF64,
};

int arch_process_options(int argc, char **argv)
{
	static const char short_options[] = KEXEC_ARCH_OPT_STR "";
	static const struct option options[] = {
		KEXEC_ARCH_OPTIONS
		{ 0 },
	};
	int opt;
	char *cmdline = NULL;
	const char *append = NULL;

	while ((opt = getopt_long(argc, argv, short_options,
				  options, 0)) != -1) {
		switch (opt) {
		case OPT_APPEND:
			append = optarg;
			break;
		case OPT_REUSE_CMDLINE:
			cmdline = get_command_line();
			break;
		case OPT_DTB:
			arch_options.dtb = optarg;
			break;
		case OPT_INITRD:
			arch_options.initrd_file = optarg;
			break;
		default:
			break;
		}
	}

	arch_options.command_line = concat_cmdline(cmdline, append);

	dbgprintf("%s:%d: command_line: %s\n", __func__, __LINE__,
		arch_options.command_line);
	dbgprintf("%s:%d: initrd: %s\n", __func__, __LINE__,
		arch_options.initrd_file);

	return 0;
}

const struct arch_map_entry arches[] = {
	{ "loongarch64", KEXEC_ARCH_LOONGARCH },
	{ NULL, 0 },
};

/*
 * struct dtb - Info about a binary device tree.
 *
 * @buf: Device tree data.
 * @size: Device tree data size.
 * @name: Shorthand name of this dtb for messages.
 * @path: Filesystem path.
 */

struct dtb {
	char *buf;
	off_t size;
	const char *name;
	const char *path;
};

/*
 * set_bootargs - Set the dtb's bootargs.
 */

static int set_bootargs(struct dtb *dtb, const char *command_line)
{
	int result;

	if (!command_line || !command_line[0])
		return 0;

	result = dtb_set_bootargs(&dtb->buf, &dtb->size, command_line);

	if (result) {
		fprintf(stderr,
			"kexec: Set device tree bootargs failed.\n");
		return EFAILED;
	}

	return 0;
}

/*
 * read_sys_dtb - Read /sys/firmware/fdt.
 */

static int read_sys_dtb(struct dtb *dtb)
{
	int result;
	struct stat s;
	static const char path[] = "/sys/firmware/fdt";

	result = stat(path, &s);

	if (result) {
		dbgprintf("%s: %s\n", __func__, strerror(errno));
		return EFAILED;
	}

	dtb->path = path;
	dtb->buf = slurp_file(path, &dtb->size);

	return 0;
}

/*
 * read_1st_dtb - Read the 1st stage kernel's dtb.
 */

static int read_1st_dtb(struct dtb *dtb)
{
	int result;

	dtb->name = "dtb_sys";
	result = read_sys_dtb(dtb);

	if (!result)
		goto on_success;

	dbgprintf("%s: not found\n", __func__);
	return EFAILED;

on_success:
	dbgprintf("%s: found %s\n", __func__, dtb->path);
	return 0;
}

static int get_cells_size(void *fdt, uint32_t *address_cells,
						uint32_t *size_cells)
{
	int nodeoffset;
	const uint32_t *prop = NULL;
	int prop_len;

	/* default values */
	*address_cells = ROOT_NODE_ADDR_CELLS_DEFAULT;
	*size_cells = ROOT_NODE_SIZE_CELLS_DEFAULT;

	/* under root node */
	nodeoffset = fdt_path_offset(fdt, "/");
	if (nodeoffset < 0)
		goto on_error;

	prop = fdt_getprop(fdt, nodeoffset, PROP_ADDR_CELLS, &prop_len);
	if (prop) {
		if (prop_len == sizeof(*prop))
			*address_cells = fdt32_to_cpu(*prop);
		else
			goto on_error;
	}

	prop = fdt_getprop(fdt, nodeoffset, PROP_SIZE_CELLS, &prop_len);
	if (prop) {
		if (prop_len == sizeof(*prop))
			*size_cells = fdt32_to_cpu(*prop);
		else
			goto on_error;
	}

	dbgprintf("%s: #address-cells:%d #size-cells:%d\n", __func__,
			*address_cells, *size_cells);
	return 0;

on_error:
	return EFAILED;
}

static bool cells_size_fitted(uint32_t address_cells, uint32_t size_cells,
						struct memory_range *range)
{
	dbgprintf("%s: %llx-%llx\n", __func__, range->start, range->end);

	/* if *_cells >= 2, cells can hold 64-bit values anyway */
	if ((address_cells == 1) && (range->start >= (1ULL << 32)))
		return false;

	if ((size_cells == 1) &&
			((range->end - range->start + 1) >= (1ULL << 32)))
		return false;

	return true;
}

static void fill_property(void *buf, uint64_t val, uint32_t cells)
{
	uint32_t val32;
	int i;

	if (cells == 1) {
		val32 = cpu_to_fdt32((uint32_t)val);
		memcpy(buf, &val32, sizeof(uint32_t));
	} else {
		for (i = 0;
		     i < (cells * sizeof(uint32_t) - sizeof(uint64_t)); i++)
			*(char *)buf++ = 0;

		val = cpu_to_fdt64(val);
		memcpy(buf, &val, sizeof(uint64_t));
	}
}

static int fdt_setprop_ranges(void *fdt, int nodeoffset, const char *name,
				struct memory_range *ranges, int nr_ranges, bool reverse,
				uint32_t address_cells, uint32_t size_cells)
{
	void *buf, *prop;
	size_t buf_size;
	int i, result;
	struct memory_range *range;

	buf_size = (address_cells + size_cells) * sizeof(uint32_t) * nr_ranges;
	prop = buf = xmalloc(buf_size);
	if (!buf)
		return -ENOMEM;

	for (i = 0; i < nr_ranges; i++) {
		if (reverse)
			range = ranges + (nr_ranges - 1 - i);
		else
			range = ranges + i;

		fill_property(prop, range->start, address_cells);
		prop += address_cells * sizeof(uint32_t);

		fill_property(prop, range->end - range->start + 1, size_cells);
		prop += size_cells * sizeof(uint32_t);
	}

	result = fdt_setprop(fdt, nodeoffset, name, buf, buf_size);

	free(buf);

	return result;
}

/*
 * setup_2nd_dtb - Setup the 2nd stage kernel's dtb.
 */

static int setup_2nd_dtb(struct dtb *dtb, char *command_line, int on_crash)
{
	uint32_t address_cells, size_cells;
	char *new_buf = NULL;
	int range_len;
	int nodeoffset;
	int new_size;
	int i, result;

	result = fdt_check_header(dtb->buf);

	if (result) {
		fprintf(stderr, "kexec: Invalid 2nd device tree.\n");
		return EFAILED;
	}

	result = set_bootargs(dtb, command_line);
	if (result) {
		fprintf(stderr, "kexec: cannot set bootargs.\n");
		result = -EINVAL;
		goto on_error;
	}

	/* determine #address-cells and #size-cells */
	result = get_cells_size(dtb->buf, &address_cells, &size_cells);
	if (result) {
		fprintf(stderr, "kexec: cannot determine cells-size.\n");
		result = -EINVAL;
		goto on_error;
	}

	if (!cells_size_fitted(address_cells, size_cells,
				&elfcorehdr_mem)) {
		fprintf(stderr, "kexec: elfcorehdr doesn't fit cells-size.\n");
		result = -EINVAL;
		goto on_error;
	}

	for (i = 0; i < usablemem_rgns.size; i++) {
		if (!cells_size_fitted(address_cells, size_cells,
					&crash_reserved_mem[i])) {
			fprintf(stderr, "kexec: usable memory range doesn't fit cells-size.\n");
			result = -EINVAL;
			goto on_error;
		}
	}

	/* duplicate dt blob */
	range_len = sizeof(uint32_t) * (address_cells + size_cells);
	new_size = fdt_totalsize(dtb->buf)
		+ fdt_prop_len(PROP_ELFCOREHDR, range_len)
		+ fdt_prop_len(PROP_USABLE_MEM_RANGE, range_len * usablemem_rgns.size);

	new_buf = xmalloc(new_size);
	result = fdt_open_into(dtb->buf, new_buf, new_size);
	if (result) {
		dbgprintf("%s: fdt_open_into failed: %s\n", __func__,
				fdt_strerror(result));
		result = -ENOSPC;
		goto on_error;
	}

	if (on_crash) {
		/* add linux,elfcorehdr */
		nodeoffset = fdt_path_offset(new_buf, "/chosen");
		result = fdt_setprop_ranges(new_buf, nodeoffset,
				PROP_ELFCOREHDR, &elfcorehdr_mem, 1, false,
				address_cells, size_cells);
		if (result) {
			dbgprintf("%s: fdt_setprop failed: %s\n", __func__,
					fdt_strerror(result));
			result = -EINVAL;
			goto on_error;
		}

		/*
		 * add linux,usable-memory-range
		 *
		 * crash dump kernel support one or two regions, to make
		 * compatibility with existing user-space and older kdump, the
		 * low region is always the last one.
		 */
		nodeoffset = fdt_path_offset(new_buf, "/chosen");
		result = fdt_setprop_ranges(new_buf, nodeoffset,
				PROP_USABLE_MEM_RANGE,
				usablemem_rgns.ranges, usablemem_rgns.size, true,
				address_cells, size_cells);
		if (result) {
			dbgprintf("%s: fdt_setprop failed: %s\n", __func__,
					fdt_strerror(result));
			result = -EINVAL;
			goto on_error;
		}
	}

	fdt_pack(new_buf);
	dtb->buf = new_buf;
	dtb->size = fdt_totalsize(new_buf);

	return result;

on_error:
        fprintf(stderr, "kexec: %s failed.\n", __func__);
        return result;
}

unsigned long loongarch_locate_kernel_segment(struct kexec_info *info)
{
	unsigned long hole;

	if (info->kexec_flags & KEXEC_ON_CRASH) {
		unsigned long hole_end;

		hole = (crash_reserved_mem[usablemem_rgns.size - 1].start < mem_min ?
				mem_min : crash_reserved_mem[usablemem_rgns.size - 1].start);
		hole = _ALIGN_UP(hole, MiB(1));
		hole_end = hole + loongarch_mem.text_offset + loongarch_mem.image_size;

		if ((hole_end > mem_max) ||
		    (hole_end > crash_reserved_mem[usablemem_rgns.size - 1].end)) {
			dbgprintf("%s: Crash kernel out of range\n", __func__);
			hole = ULONG_MAX;
		}
	} else {
		hole = locate_hole(info,
			loongarch_mem.text_offset + loongarch_mem.image_size,
			MiB(1), 0, ULONG_MAX, 1);

		if (hole == ULONG_MAX)
			dbgprintf("%s: locate_hole failed\n", __func__);
	}

	return hole;
}

/*
 * loongarch_load_other_segments - Prepare the dtb and initrd segments.
 */

int loongarch_load_other_segments(struct kexec_info *info, unsigned long hole_min)
{
	int result;
	unsigned long dtb_base, initrd_min;
	unsigned long hole_max;
	char *initrd_buf = NULL;
	struct dtb dtb;
	char command_line[COMMAND_LINE_SIZE] = "";
	unsigned long pagesize = getpagesize();

	if (arch_options.command_line) {
		if (strlen(arch_options.command_line) >
		    sizeof(command_line) - 1) {
			fprintf(stderr,
				"Kernel command line too long for kernel!\n");
			return EFAILED;
		}

		strncpy(command_line, arch_options.command_line,
			sizeof(command_line) - 1);
		command_line[sizeof(command_line) - 1] = 0;
	}

	if (arch_options.dtb) {
		dtb.name = "dtb_user";
		dtb.buf = slurp_file(arch_options.dtb, &dtb.size);
	} else {
		result = read_1st_dtb(&dtb);

		if (result) {
			fprintf(stderr,
				"kexec: Error: No device tree available.\n");
			return EFAILED;
		}
	}

	result = setup_2nd_dtb(&dtb, command_line,
			       info->kexec_flags & KEXEC_ON_CRASH);
	if (result)
		return EFAILED;

	/* Put the other segments after the image. */

	initrd_min = hole_min;
	if (info->kexec_flags & KEXEC_ON_CRASH)
		hole_max = crash_reserved_mem[usablemem_rgns.size - 1].end;
	else
		hole_max = ULONG_MAX;

	if (arch_options.initrd_file) {

		initrd_buf = slurp_decompress_file(arch_options.initrd_file, &initrd_size);

		initrd_base = add_buffer(info, initrd_buf, initrd_size,
					initrd_size, sizeof(void *),
					_ALIGN_UP(initrd_min,
						pagesize), hole_max, 1);
		dbgprintf("initrd_base: %lx, initrd_size: %lx\n", initrd_base, initrd_size);

		result = dtb_set_initrd((char **)&dtb.buf, &dtb.size, initrd_base,
				initrd_base + initrd_size);
		if (result)
			return EFAILED;
	}

	/* Check size limit. */
	if (dtb.size > KiB(64)) {
		fprintf(stderr, "kexec: Error: dtb too big.\n");
		return EFAILED;
	}

	dtb_base = add_buffer(info, dtb.buf, dtb.size, dtb.size,
		sizeof(void *), _ALIGN_UP(hole_min, getpagesize()),
		0xffffffff, 1);

	/* dtb_base is valid if we got here. */
	dbgprintf("dtb:    base %lx, size %lxh (%ld)\n", dtb_base, dtb.size,
		dtb.size);

	return 0;

}

int arch_compat_trampoline(struct kexec_info *UNUSED(info))
{
	return 0;
}

void arch_update_purgatory(struct kexec_info *UNUSED(info))
{
}

unsigned long virt_to_phys(unsigned long addr)
{
	return addr & ((1ULL << 48) - 1);
}

/*
 * add_segment() should convert base to a physical address on loongarch,
 * while the default is just to work with base as is
 */
void add_segment(struct kexec_info *info, const void *buf, size_t bufsz,
		 unsigned long base, size_t memsz)
{
	add_segment_phys_virt(info, buf, bufsz, virt_to_phys(base), memsz, 1);
}

/*
 * add_buffer() should convert base to a physical address on loongarch,
 * while the default is just to work with base as is
 */
unsigned long add_buffer(struct kexec_info *info, const void *buf,
			 unsigned long bufsz, unsigned long memsz,
			 unsigned long buf_align, unsigned long buf_min,
			 unsigned long buf_max, int buf_end)
{
	return add_buffer_phys_virt(info, buf, bufsz, memsz, buf_align,
				    buf_min, buf_max, buf_end, 1);
}
