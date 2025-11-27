/**
 * ESLint Configuration for Banning Specific Nested Methods
 *
 * This file uses the 'no-restricted-syntax' rule to ban specific property
 * accesses and function calls, which is necessary for blocking nested
 * names like 'Memory.read' or 'Module.getBaseAddress()'.
 */
import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";

export default [
  {
    files: ["src/**/*.ts"],

    languageOptions: {
      ecmaVersion: 2020,
      sourceType: "module",
      parser: tsparser,
    },

    plugins: {
      "@typescript-eslint": tseslint,
    },

    rules: {
      // TypeScript recommended rules
      ...tseslint.configs.recommended.rules,

      // --- Core Ban Logic ---
      "no-restricted-syntax": [
        "error",

        // 1. Ban 'Memory.read' access
        {
          // Selects any MemberExpression where the object is 'Memory' and the property is 'read'.
          // This catches both 'Memory.read' as a variable/property and 'Memory.read()' as a call.
          selector:
            "MemberExpression[object.name='Memory'][property.name='read']",
          message:
            "The use of 'Memory.read' is strictly forbidden for security or architectural reasons.",
        },

        // 2. Ban specific function calls on the 'Module' object
        {
          // Selects CallExpression nodes where the function being called (callee) is a MemberExpression,
          // the object of that expression is 'Module', and the property is one of the banned names.
          selector: `CallExpression[callee.object.name='Module'][callee.property.name=/^(ensureInitialized|findBaseAddress|getBaseAddress|findExportByName|getExportByName|findSymbolByName|getSymbolByName)$/]`,
          message:
            "Direct calls to Module's memory/symbol resolution functions are forbidden.",
        },

        // 3. Ban specific property access on the 'Module' object (in case they are not called)
        {
          // This catches references to the functions without the parentheses, e.g., 'const fn = Module.getBaseAddress;'
          selector: `MemberExpression[object.name='Module'][property.name=/^(ensureInitialized|findBaseAddress|getBaseAddress|findExportByName|getExportByName|findSymbolByName|getSymbolByName)$/]`,
          message:
            "Referencing Module's memory/symbol resolution functions is forbidden.",
        },
      ],
      // Disable rules that might conflict with the banned functions if they are part of a large library
      "@typescript-eslint/no-unused-vars": "off",
      "no-undef": "off",
    },
  },
];
