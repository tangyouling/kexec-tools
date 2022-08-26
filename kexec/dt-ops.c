#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>
#include <libfdt.h>
#include <stdio.h>
#include <stdlib.h>

#include "kexec.h"
#include "dt-ops.h"

#define ROOT_NODE_ADDR_CELLS_DEFAULT 1
#define ROOT_NODE_SIZE_CELLS_DEFAULT 1

static const char n_chosen[] = "chosen";

static const char p_bootargs[] = "bootargs";
static const char p_initrd_start[] = "linux,initrd-start";
static const char p_initrd_end[] = "linux,initrd-end";
static const char p_address_cells[] = "#address-cells";
static const char p_size_cells[] = "#size-cells";

int dtb_set_initrd(char **dtb, off_t *dtb_size, off_t start, off_t end)
{
	int result;
	uint64_t value;

	dbgprintf("%s: start %jd, end %jd, size %jd (%jd KiB)\n",
		__func__, (intmax_t)start, (intmax_t)end,
		(intmax_t)(end - start),
		(intmax_t)(end - start) / 1024);

	value = cpu_to_fdt64(start);

	result = dtb_set_property(dtb, dtb_size, n_chosen, p_initrd_start,
		&value, sizeof(value));

	if (result)
		return result;

	value = cpu_to_fdt64(end);

	result = dtb_set_property(dtb, dtb_size, n_chosen, p_initrd_end,
		&value, sizeof(value));

	if (result) {
		dtb_delete_property(*dtb, n_chosen, p_initrd_start);
		return result;
	}

	return 0;
}

void dtb_clear_initrd(char **dtb, off_t *dtb_size)
{
	dtb_delete_property(*dtb, n_chosen, p_initrd_start);
	dtb_delete_property(*dtb, n_chosen, p_initrd_end);
}

int dtb_set_bootargs(char **dtb, off_t *dtb_size, const char *command_line)
{
	return dtb_set_property(dtb, dtb_size, n_chosen, p_bootargs,
		command_line, strlen(command_line) + 1);
}

int dtb_set_property(char **dtb, off_t *dtb_size, const char *node,
	const char *prop, const void *value, int value_len)
{
	int result;
	int nodeoffset;
	void *new_dtb;
	int new_size;
	char *new_node = NULL;

	value_len = FDT_TAGALIGN(value_len);

	new_size = FDT_TAGALIGN(*dtb_size + fdt_node_len(node)
		+ fdt_prop_len(prop, value_len));

	new_dtb = malloc(new_size);

	if (!new_dtb) {
		dbgprintf("%s: malloc failed\n", __func__);
		return -ENOMEM;
	}

	result = fdt_open_into(*dtb, new_dtb, new_size);

	if (result) {
		dbgprintf("%s: fdt_open_into failed: %s\n", __func__,
			fdt_strerror(result));
		goto on_error;
	}

	new_node = malloc(strlen("/") + strlen(node) + 1);
	if (!new_node) {
		dbgprintf("%s: malloc failed\n", __func__);
		result = -ENOMEM;
		goto on_error;
	}

	strcpy(new_node, "/");
	strcat(new_node, node);
	
	nodeoffset = fdt_path_offset(new_dtb, new_node);

	if (nodeoffset == -FDT_ERR_NOTFOUND) {
		result = fdt_add_subnode(new_dtb, 0, node);

		if (result < 0) {
			dbgprintf("%s: fdt_add_subnode failed: %s\n", __func__,
				fdt_strerror(result));
			goto on_error;
		}
		nodeoffset = result;
	} else if (nodeoffset < 0) {
		dbgprintf("%s: fdt_path_offset failed: %s\n", __func__,
			fdt_strerror(nodeoffset));
		goto on_error;
	}

	result = fdt_setprop(new_dtb, nodeoffset, prop, value, value_len);

	if (result) {
		dbgprintf("%s: fdt_setprop failed: %s\n", __func__,
			fdt_strerror(result));
		goto on_error;
	}

	/*
	 * Can't call free on dtb since dtb may have been mmaped by
	 * slurp_file().
	 */

	result = fdt_pack(new_dtb);

	if (result)
		dbgprintf("%s: Unable to pack device tree: %s\n", __func__,
			fdt_strerror(result));

	*dtb = new_dtb;
	*dtb_size = fdt_totalsize(*dtb);

	return 0;

on_error:
	free(new_dtb);
	free(new_node);
	return result;
}

int dtb_delete_property(char *dtb, const char *node, const char *prop)
{
	int result, nodeoffset;
	char *new_node = NULL;

	new_node = malloc(strlen("/") + strlen(node) + 1);
	if (!new_node) {
		dbgprintf("%s: malloc failed\n", __func__);
		return -ENOMEM;
	}

	strcpy(new_node, "/");
	strcat(new_node, node);

	nodeoffset = fdt_path_offset(dtb, new_node);
	if (nodeoffset < 0) {
		dbgprintf("%s: fdt_path_offset failed: %s\n", __func__,
			fdt_strerror(nodeoffset));
		free(new_node);
		return nodeoffset;
	}

	result = fdt_delprop(dtb, nodeoffset, prop);

	if (result)
		dbgprintf("%s: fdt_delprop failed: %s\n", __func__,
			fdt_strerror(nodeoffset));

	free(new_node);
	return result;
}

int get_cells_size(void *fdt, uint32_t *address_cells, uint32_t *size_cells)
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

	prop = fdt_getprop(fdt, nodeoffset, p_address_cells, &prop_len);
	if (prop) {
		if (prop_len == sizeof(*prop))
			*address_cells = fdt32_to_cpu(*prop);
		else
			goto on_error;
	}

	prop = fdt_getprop(fdt, nodeoffset, p_size_cells, &prop_len);
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

bool cells_size_fitted(uint32_t address_cells, uint32_t size_cells,
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

int fdt_setprop_ranges(void *fdt, int nodeoffset, const char *name,
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
