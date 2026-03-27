/*
 * WASM wrapper for libhbc (WASI build).
 * Returns JSON strings to avoid struct marshaling across the WASM boundary.
 * All returned strings are malloc'd — caller frees via hbc_wasm_free().
 */

#include <hbc/hbc.h>
#include <hbc/common.h>
#include <hbc/disasm.h>

/* Access HBC internals to reach the embedded HBCReader for disassembly */
#include "../r2hermes/src/lib/hbc_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPORT(name) __attribute__((export_name(#name)))

#define MAX_HANDLES 16
static HBC *handles[MAX_HANDLES] = {0};

static int alloc_handle(HBC *hbc) {
	for (int i = 0; i < MAX_HANDLES; i++) {
		if (!handles[i]) {
			handles[i] = hbc;
			return i;
		}
	}
	return -1;
}

static HBC *get_handle(int h) {
	if (h < 0 || h >= MAX_HANDLES) return NULL;
	return handles[h];
}

/* StringBuffer helpers */
#define SB_INIT(sb) _hbc_string_buffer_init(&(sb), 1024)
#define SB_APPEND(sb, s) _hbc_string_buffer_append(&(sb), (s))
#define SB_APPEND_CHAR(sb, c) _hbc_string_buffer_append_char(&(sb), (c))
#define SB_APPEND_INT(sb, v) _hbc_string_buffer_append_int(&(sb), (v))
#define SB_FREE(sb) _hbc_string_buffer_free(&(sb))

static char *sb_finish(StringBuffer *sb) {
	char *result = strdup(sb->data);
	SB_FREE(*sb);
	return result;
}

/* Escape a string for JSON output */
static void json_escape(StringBuffer *sb, const char *s) {
	SB_APPEND_CHAR(*sb, '"');
	if (!s) {
		SB_APPEND_CHAR(*sb, '"');
		return;
	}
	for (; *s; s++) {
		switch (*s) {
		case '"': SB_APPEND(*sb, "\\\""); break;
		case '\\': SB_APPEND(*sb, "\\\\"); break;
		case '\n': SB_APPEND(*sb, "\\n"); break;
		case '\r': SB_APPEND(*sb, "\\r"); break;
		case '\t': SB_APPEND(*sb, "\\t"); break;
		case '\b': SB_APPEND(*sb, "\\b"); break;
		case '\f': SB_APPEND(*sb, "\\f"); break;
		default:
			if ((unsigned char)*s < 0x20) {
				char buf[8];
				snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)*s);
				SB_APPEND(*sb, buf);
			} else {
				SB_APPEND_CHAR(*sb, *s);
			}
			break;
		}
	}
	SB_APPEND_CHAR(*sb, '"');
}

/* --- Public API --- */

EXPORT(hbc_wasm_open)
int hbc_wasm_open(const unsigned char *data, int size) {
	HBC *hbc = NULL;
	Result res = hbc_open_from_memory(data, (size_t)size, &hbc);
	if (res.code != RESULT_SUCCESS || !hbc) return -1;
	int h = alloc_handle(hbc);
	if (h < 0) {
		hbc_close(hbc);
		return -1;
	}
	return h;
}

EXPORT(hbc_wasm_info)
char *hbc_wasm_info(int handle) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return strdup("{\"error\":\"invalid handle\"}");

	HBCHeader hdr;
	Result res = hbc_get_header(hbc, &hdr);
	if (res.code != RESULT_SUCCESS)
		return strdup("{\"error\":\"failed to get header\"}");

	char hash[41];
	for (int i = 0; i < 20; i++)
		snprintf(hash + i * 2, 3, "%02x", hdr.sourceHash[i]);

	char *buf = (char *)malloc(512);
	if (!buf) return NULL;
	snprintf(buf, 512,
		"{\"version\":%u,\"sourceHash\":\"%s\",\"fileLength\":%u,"
		"\"globalCodeIndex\":%u,\"functionCount\":%u,\"stringCount\":%u,"
		"\"identifierCount\":%u,\"overflowStringCount\":%u,"
		"\"regExpCount\":%u,\"cjsModuleCount\":%u,"
		"\"hasAsync\":%s,\"staticBuiltins\":%s}",
		hdr.version, hash, hdr.fileLength,
		hdr.globalCodeIndex, hdr.functionCount, hdr.stringCount,
		hdr.identifierCount, hdr.overflowStringCount,
		hdr.regExpCount, hdr.cjsModuleCount,
		hdr.hasAsync ? "true" : "false",
		hdr.staticBuiltins ? "true" : "false");
	return buf;
}

EXPORT(hbc_wasm_functions)
char *hbc_wasm_functions(int handle) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return strdup("[]");

	u32 count = hbc_function_count(hbc);
	StringBuffer sb;
	SB_INIT(sb);
	SB_APPEND_CHAR(sb, '[');

	for (u32 i = 0; i < count; i++) {
		HBCFunc func;
		Result res = hbc_get_function_info(hbc, i, &func);
		if (res.code != RESULT_SUCCESS) continue;

		if (i > 0) SB_APPEND_CHAR(sb, ',');
		SB_APPEND(sb, "{\"id\":");
		SB_APPEND_INT(sb, (int)i);
		SB_APPEND(sb, ",\"name\":");
		json_escape(&sb, func.name);
		SB_APPEND(sb, ",\"offset\":");
		SB_APPEND_INT(sb, (int)func.offset);
		SB_APPEND(sb, ",\"size\":");
		SB_APPEND_INT(sb, (int)func.size);
		SB_APPEND(sb, ",\"paramCount\":");
		SB_APPEND_INT(sb, (int)func.param_count);
		SB_APPEND_CHAR(sb, '}');
	}

	SB_APPEND_CHAR(sb, ']');
	return sb_finish(&sb);
}

EXPORT(hbc_wasm_strings)
char *hbc_wasm_strings(int handle) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return strdup("[]");

	u32 count = hbc_string_count(hbc);
	StringBuffer sb;
	SB_INIT(sb);
	SB_APPEND_CHAR(sb, '[');

	for (u32 i = 0; i < count; i++) {
		const char *str = NULL;
		Result res = hbc_get_string(hbc, i, &str);
		if (res.code != RESULT_SUCCESS) continue;

		HBCStringMeta meta;
		const char *kind = "string";
		if (hbc_get_string_meta(hbc, i, &meta).code == RESULT_SUCCESS) {
			switch (meta.kind) {
			case HERMES_STRING_KIND_IDENTIFIER: kind = "identifier"; break;
			case HERMES_STRING_KIND_PREDEFINED: kind = "predefined"; break;
			default: break;
			}
		}

		if (i > 0) SB_APPEND_CHAR(sb, ',');
		SB_APPEND(sb, "{\"index\":");
		SB_APPEND_INT(sb, (int)i);
		SB_APPEND(sb, ",\"value\":");
		json_escape(&sb, str);
		SB_APPEND(sb, ",\"kind\":\"");
		SB_APPEND(sb, kind);
		SB_APPEND(sb, "\"}");
	}

	SB_APPEND_CHAR(sb, ']');
	return sb_finish(&sb);
}

EXPORT(hbc_wasm_decompile)
char *hbc_wasm_decompile(int handle, int function_id) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return strdup("// invalid handle");

	HBCDecompOptions opts;
	memset(&opts, 0, sizeof(opts));
	opts.pretty_literals = true;
	opts.inline_closures = true;

	char *output = NULL;
	Result res = hbc_decomp_fn(hbc, (u32)function_id, opts, &output);
	if (res.code != RESULT_SUCCESS || !output)
		return strdup("// decompilation failed");
	return output;
}

EXPORT(hbc_wasm_decompile_all)
char *hbc_wasm_decompile_all(int handle) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return strdup("// invalid handle");

	HBCDecompOptions opts;
	memset(&opts, 0, sizeof(opts));
	opts.pretty_literals = true;
	opts.inline_closures = true;

	char *output = NULL;
	Result res = hbc_decomp_all(hbc, opts, &output);
	if (res.code != RESULT_SUCCESS || !output)
		return strdup("// decompilation failed");
	return output;
}

EXPORT(hbc_wasm_decompile_offsets)
char *hbc_wasm_decompile_offsets(int handle, int function_id) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return strdup("// invalid handle");

	HBCDecompOptions opts;
	memset(&opts, 0, sizeof(opts));
	opts.pretty_literals = true;
	opts.inline_closures = true;
	opts.show_offsets = true;

	char *output = NULL;
	Result res = hbc_decomp_fn(hbc, (u32)function_id, opts, &output);
	if (res.code != RESULT_SUCCESS || !output)
		return strdup("// decompilation failed");
	return output;
}

EXPORT(hbc_wasm_decompile_offsets_all)
char *hbc_wasm_decompile_offsets_all(int handle) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return strdup("// invalid handle");

	HBCDecompOptions opts;
	memset(&opts, 0, sizeof(opts));
	opts.pretty_literals = true;
	opts.inline_closures = true;
	opts.show_offsets = true;

	char *output = NULL;
	Result res = hbc_decomp_all(hbc, opts, &output);
	if (res.code != RESULT_SUCCESS || !output)
		return strdup("// decompilation failed");
	return output;
}

/*
 * Disassemble a single function.
 * Uses the Disassembler from decoder.c with the HBCReader inside HBC.
 */
EXPORT(hbc_wasm_disassemble)
char *hbc_wasm_disassemble(int handle, int function_id) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return strdup("; invalid handle");

	HBCDisOptions dis_opts;
	memset(&dis_opts, 0, sizeof(dis_opts));
	dis_opts.asm_syntax = true;
	dis_opts.resolve_string_ids = true;

	Disassembler dis;
	Result res = _hbc_disassembler_init(&dis, &hbc->reader, dis_opts);
	if (res.code != RESULT_SUCCESS)
		return strdup("; disassembler init failed");

	res = _hbc_disassemble_function(&dis, (u32)function_id);
	if (res.code != RESULT_SUCCESS) {
		_hbc_disassembler_cleanup(&dis);
		return strdup("; disassembly failed");
	}

	char *output = strdup(dis.output.data ? dis.output.data : "");
	_hbc_disassembler_cleanup(&dis);
	return output;
}

EXPORT(hbc_wasm_disassemble_all)
char *hbc_wasm_disassemble_all(int handle) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return strdup("; invalid handle");

	HBCDisOptions dis_opts;
	memset(&dis_opts, 0, sizeof(dis_opts));
	dis_opts.asm_syntax = true;
	dis_opts.resolve_string_ids = true;

	Disassembler dis;
	Result res = _hbc_disassembler_init(&dis, &hbc->reader, dis_opts);
	if (res.code != RESULT_SUCCESS)
		return strdup("; disassembler init failed");

	res = _hbc_disassemble_all_functions(&dis);
	if (res.code != RESULT_SUCCESS) {
		_hbc_disassembler_cleanup(&dis);
		return strdup("; disassembly failed");
	}

	char *output = strdup(dis.output.data ? dis.output.data : "");
	_hbc_disassembler_cleanup(&dis);
	return output;
}

EXPORT(hbc_wasm_close)
void hbc_wasm_close(int handle) {
	HBC *hbc = get_handle(handle);
	if (!hbc) return;
	hbc_close(hbc);
	handles[handle] = NULL;
}

EXPORT(hbc_wasm_free)
void hbc_wasm_free(char *ptr) {
	free(ptr);
}
