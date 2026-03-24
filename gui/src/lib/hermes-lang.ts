/**
 * Monaco language definition for Hermes bytecode disassembly.
 * Generated from r2hermes opcode tables (v51–v99).
 */
import type { languages } from "monaco-editor";

export const HERMES_LANGUAGE_ID = "hermes-bytecode";

export const monarchTokens: languages.IMonarchLanguage = {
  defaultToken: "",
  ignoreCase: false,

  keywords: [
    // --- Control flow ---
    "jmp", "jmp_long", "jmp_true", "jmp_true_long", "jmp_false", "jmp_false_long",
    "jmp_undefined", "jmp_undefined_long", "jmp_builtin_is", "jmp_builtin_is_long",
    "jmp_builtin_is_not", "jmp_builtin_is_not_long", "jmp_type_of_is",
    "j_equal", "j_equal_long", "j_not_equal", "j_not_equal_long",
    "j_strict_equal", "j_strict_equal_long", "j_strict_not_equal", "j_strict_not_equal_long",
    "j_less", "j_less_long", "j_less_n", "j_less_n_long",
    "j_less_equal", "j_less_equal_long", "j_less_equal_n", "j_less_equal_n_long",
    "j_greater", "j_greater_long", "j_greater_n", "j_greater_n_long",
    "j_greater_equal", "j_greater_equal_long", "j_greater_equal_n", "j_greater_equal_n_long",
    "j_not_less", "j_not_less_long", "j_not_less_n", "j_not_less_n_long",
    "j_not_less_equal", "j_not_less_equal_long", "j_not_less_equal_n", "j_not_less_equal_n_long",
    "j_not_greater", "j_not_greater_long", "j_not_greater_n", "j_not_greater_n_long",
    "j_not_greater_equal", "j_not_greater_equal_long", "j_not_greater_equal_n", "j_not_greater_equal_n_long",
    // Legacy jump names (older bytecode versions)
    "jequal", "jequal_long", "jnot_equal", "jnot_equal_long",
    "jstrict_equal", "jstrict_equal_long", "jstrict_not_equal", "jstrict_not_equal_long",
    "jless", "jless_long", "jless_n", "jless_nlong",
    "jless_equal", "jless_equal_long", "jless_equal_n", "jless_equal_nlong",
    "jgreater", "jgreater_long", "jgreater_n", "jgreater_nlong",
    "jgreater_equal", "jgreater_equal_long", "jgreater_equal_n", "jgreater_equal_nlong",
    "jnot_less", "jnot_less_long", "jnot_less_n", "jnot_less_nlong",
    "jnot_less_equal", "jnot_less_equal_long", "jnot_less_equal_n", "jnot_less_equal_nlong",
    "jnot_greater", "jnot_greater_long", "jnot_greater_n", "jnot_greater_nlong",
    "jnot_greater_equal", "jnot_greater_equal_long", "jnot_greater_equal_n", "jnot_greater_equal_nlong",
    "switch_imm", "u_int_switch_imm", "string_switch_imm",
    "ret", "throw", "throw_if_empty", "throw_if_undefined", "throw_if_undefined_inst",
    "throw_if_has_restricted_global_property", "throw_if_this_initialized",
    "catch", "unreachable",
    // --- Calls ---
    "call", "call_long", "call1", "call2", "call3", "call4",
    "call_direct", "call_direct_long_index",
    "call_builtin", "call_builtin_long",
    "call_require", "call_with_new_target", "call_with_new_target_long",
    "construct", "construct_long", "direct_eval",
    // --- Load/Store ---
    "mov", "mov_long",
    "load_const_undefined", "load_const_null", "load_const_true", "load_const_false",
    "load_const_zero", "load_const_empty",
    "load_const_u_int8", "load_const_uint8", "load_const_int", "load_const_double",
    "load_const_string", "load_const_string_long_index",
    "load_const_big_int", "load_const_big_int_long_index",
    "load_param", "load_param_long",
    "load_from_environment", "load_from_environment_l",
    "load_this_n_s", "load_this_ns", "load_parent_no_traps",
    "store_to_environment", "store_to_environment_l",
    "store_n_pto_environment", "store_n_pto_environment_l",
    "store_np_to_environment", "store_np_to_environment_l",
    "loadi8", "loadi16", "loadi32", "loadu8", "loadu16", "loadu32",
    "store8", "store16", "store32",
    // --- Property access ---
    "get_by_id", "get_by_id_long", "get_by_id_short", "get_by_id_with_receiver_long",
    "get_by_val", "get_by_val_with_receiver", "get_by_index",
    "try_get_by_id", "try_get_by_id_long",
    "put_by_id", "put_by_id_long", "put_by_id_loose", "put_by_id_loose_long",
    "put_by_id_strict", "put_by_id_strict_long",
    "put_by_val", "put_by_val_loose", "put_by_val_strict", "put_by_val_with_receiver",
    "try_put_by_id", "try_put_by_id_long",
    "try_put_by_id_loose", "try_put_by_id_loose_long",
    "try_put_by_id_strict", "try_put_by_id_strict_long",
    "put_new_own_by_id", "put_new_own_by_id_long", "put_new_own_by_id_short",
    "put_new_own_n_eby_id", "put_new_own_n_eby_id_long",
    "put_new_own_ne_by_id", "put_new_own_ne_by_id_long",
    "put_own_by_index", "put_own_by_index_l",
    "put_own_by_val", "put_own_by_slot_idx", "put_own_by_slot_idx_long",
    "put_own_getter_setter_by_val",
    "del_by_id", "del_by_id_long", "del_by_id_loose", "del_by_id_loose_long",
    "del_by_id_strict", "del_by_id_strict_long", "del_by_val", "del_by_val_loose", "del_by_val_strict",
    "define_own_by_id", "define_own_by_id_long",
    "define_own_by_index", "define_own_by_index_l",
    "define_own_by_val", "define_own_getter_setter_by_val",
    "define_own_in_dense_array", "define_own_in_dense_array_l",
    "get_own_by_slot_idx", "get_own_by_slot_idx_long",
    "get_own_private_by_sym", "put_own_private_by_sym", "add_own_private_by_sym",
    "private_is_in",
    // --- Environment / closures ---
    "get_environment", "get_parent_environment", "get_closure_environment",
    "create_environment", "create_inner_environment",
    "create_function_environment", "create_top_level_environment",
    "create_closure", "create_closure_long_index",
    "create_async_closure", "create_async_closure_long_index",
    "create_generator_closure", "create_generator_closure_long_index",
    "get_builtin_closure",
    // --- Object / array creation ---
    "new_object", "new_object_with_buffer", "new_object_with_buffer_long",
    "new_object_with_parent", "new_object_with_buffer_and_parent",
    "new_typed_object_with_buffer",
    "new_array", "new_array_with_buffer", "new_array_with_buffer_long",
    "new_fast_array",
    "create_reg_exp", "create_this", "create_this_for_new", "create_this_for_super",
    "create_base_class", "create_base_class_long_index",
    "create_derived_class", "create_derived_class_long_index",
    "create_private_name",
    // --- Arithmetic / logic ---
    "add", "add_n", "add_s", "add_empty_string", "add32",
    "sub", "sub_n", "sub32", "mul", "mul_n", "mul32",
    "div", "div_n", "divi32", "divu32", "mod",
    "inc", "dec", "negate", "not", "bit_not",
    "bit_and", "bit_or", "bit_xor",
    "l_shift", "lshift", "r_shift", "rshift", "u_rshift", "urshift",
    "to_number", "to_numeric", "to_int32", "to_uint32", "to_property_key",
    // --- Comparison ---
    "eq", "neq", "strict_eq", "strict_neq",
    "less", "less_eq", "greater", "greater_eq",
    "instance_of", "is_in", "type_of", "type_of_is",
    // --- Generator / async ---
    "create_generator", "create_generator_long_index",
    "save_generator", "save_generator_long",
    "start_generator", "resume_generator", "complete_generator",
    "async_break_check",
    // --- Iterators ---
    "iterator_begin", "iterator_next", "iterator_close",
    // --- Arguments ---
    "reify_arguments", "reify_arguments_loose", "reify_arguments_strict",
    "get_arguments_length", "get_arguments_prop_by_val",
    "get_arguments_prop_by_val_loose", "get_arguments_prop_by_val_strict",
    // --- Misc ---
    "get_global_object", "get_new_target",
    "declare_global_var", "select_object",
    "coerce_this_n_s", "coerce_this_ns",
    "get_p_name_list", "get_pname_list", "get_next_p_name", "get_next_pname",
    "debugger", "debugger_check", "debugger_check_break",
    "profile_point", "name",
    // --- Fast arrays ---
    "fast_array_load", "fast_array_store", "fast_array_push",
    "fast_array_append", "fast_array_length",
    // --- Typed load ---
    "typed_load_parent",
  ],

  registers: /r\d{1,3}/,

  tokenizer: {
    root: [
      // Comments: lines starting with #
      [/#.*$/, "comment"],

      // Function header: => [Function #N: ...
      [/^=>.*$/, "type.identifier"],

      // Section header: "Bytecode listing" etc
      [/^Bytecode listing.*:$/, "type.identifier"],

      // Offset annotation: @ offset 0x...
      [/@\s+offset\s+0x[0-9a-fA-F]+/, "type.identifier"],

      // Address at start of line: 0x00055400:
      [/^\s*0x[0-9a-fA-F]+:/, "number.hex"],

      // Hex literals in operands
      [/0x[0-9a-fA-F]+/, "number.hex"],

      // Numeric literals
      [/-?\d+(\.\d+)?/, "number"],

      // Registers: r0, r1, ..., r255
      [/r\d{1,3}/, "variable.name"],

      // String annotations in comments
      [/"[^"]*"/, "string"],

      // Separators
      [/[,:]/, "delimiter"],

      // Instruction mnemonics (checked against keywords)
      [/[a-z_][a-z_0-9]*/, {
        cases: {
          "@keywords": "keyword",
          "@default": "identifier",
        },
      }],
    ],
  },
};
