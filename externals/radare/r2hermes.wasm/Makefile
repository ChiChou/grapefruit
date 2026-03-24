CC = emcc
CFLAGS = -std=c11 -O2 -D_POSIX_C_SOURCE=200809L
EMFLAGS = -s EXPORTED_FUNCTIONS='["_hbc_wasm_open","_hbc_wasm_info","_hbc_wasm_functions","_hbc_wasm_strings","_hbc_wasm_decompile","_hbc_wasm_decompile_all","_hbc_wasm_decompile_offsets","_hbc_wasm_decompile_offsets_all","_hbc_wasm_disassemble","_hbc_wasm_disassemble_all","_hbc_wasm_close","_hbc_wasm_free","_malloc","_free"]' \
	-s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString","HEAPU8"]' \
	-s MODULARIZE=1 \
	-s EXPORT_NAME=createHBCModule \
	-s ALLOW_MEMORY_GROWTH=1 \
	-s ENVIRONMENT='web,node' \
	-s FILESYSTEM=0 \
	-s STACK_SIZE=65536

R2HERMES = ../r2hermes
INCLUDES = -I$(R2HERMES)/include -I$(R2HERMES)/src/lib
SRC = $(R2HERMES)/src/lib/utils/string_buffer.c \
	$(R2HERMES)/src/lib/utils/buffer_reader.c \
	$(R2HERMES)/src/lib/parsers/hbc_file_parser.c \
	$(R2HERMES)/src/lib/parsers/hbc_bytecode_parser.c \
	$(R2HERMES)/src/lib/opcodes/isa.c \
	$(R2HERMES)/src/lib/opcodes/encoder.c \
	$(R2HERMES)/src/lib/opcodes/decoder.c \
	$(R2HERMES)/src/lib/decompilation/decompiler.c \
	$(R2HERMES)/src/lib/decompilation/translator.c \
	$(R2HERMES)/src/lib/decompilation/token.c \
	$(R2HERMES)/src/lib/decompilation/literals.c \
	$(R2HERMES)/src/lib/hbc.c

WRAPPER = hbc_wasm.c
OUTPUT_DIR = dist
OUTPUT = $(OUTPUT_DIR)/hbc.mjs

VERSION_H = $(R2HERMES)/include/hbc/version.h

.PHONY: all clean

all: $(OUTPUT)
	@ls -lh $(OUTPUT_DIR)/hbc.*

$(OUTPUT): $(SRC) $(WRAPPER) $(VERSION_H)
	mkdir -p $(OUTPUT_DIR)
	$(CC) $(SRC) $(WRAPPER) $(CFLAGS) $(INCLUDES) $(EMFLAGS) -o $(OUTPUT)

$(VERSION_H): $(R2HERMES)/meson.build
	mkdir -p $(dir $(VERSION_H))
	@VERSION=$$(grep vers "$(R2HERMES)/meson.build" | head -1 | cut -d "'" -f 2); \
	echo "#ifndef LIBHBC_VERSION" > "$@"; \
	echo "#define LIBHBC_VERSION \"$$VERSION\"" >> "$@"; \
	echo "#define LIBHBC_VERSION_MAJOR \"$$(echo $$VERSION | cut -d . -f 1)\"" >> "$@"; \
	echo "#define LIBHBC_VERSION_MINOR \"$$(echo $$VERSION | cut -d . -f 2)\"" >> "$@"; \
	echo "#define LIBHBC_VERSION_PATCH \"$$(echo $$VERSION | cut -d . -f 3)\"" >> "$@"; \
	echo "#endif" >> "$@"

clean:
	rm -rf $(OUTPUT_DIR)
