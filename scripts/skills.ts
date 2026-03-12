import ts from "typescript";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";

const AGENT_TYPES = resolve(import.meta.dirname!, "../agent/types");

interface ParamInfo {
  name: string;
  type: string;
}

interface FuncInfo {
  name: string;
  params: ParamInfo[];
  returnType: string;
}

interface TypeDef {
  name: string;
  text: string;
}

interface ModuleResult {
  functions: FuncInfo[];
  types: TypeDef[];
}

function parseFile(filePath: string): ts.SourceFile {
  const code = readFileSync(filePath, "utf-8");
  return ts.createSourceFile(filePath, code, ts.ScriptTarget.Latest, true);
}

function typeToString(
  node: ts.TypeNode | undefined,
  src: ts.SourceFile,
): string {
  if (!node) return "any";
  return node.getText(src);
}

function paramToInfo(
  param: ts.ParameterDeclaration,
  src: ts.SourceFile,
): ParamInfo {
  const name = param.name.getText(src);
  let type = typeToString(param.type, src);
  if (param.questionToken) type += " | undefined";
  if (param.initializer) type += " | undefined";
  return { name, type };
}

function resolveImportPath(specifier: string, importerDir: string): string {
  if (specifier.startsWith("@/common/")) {
    const rel = specifier.slice("@/common/".length).replace(/\.js$/, ".d.ts");
    return resolve(AGENT_TYPES, "common", rel);
  }
  const rel = specifier.replace(/\.js$/, ".d.ts");
  return resolve(importerDir, rel);
}

function extractModule(
  filePath: string,
  emittedTypes: Set<string>,
): ModuleResult {
  if (!existsSync(filePath)) return { functions: [], types: [] };

  const src = parseFile(filePath);
  const functions: FuncInfo[] = [];
  const types: TypeDef[] = [];
  const fileDir = dirname(filePath);

  // Check for `export * from` re-exports and follow them
  for (const stmt of src.statements) {
    if (
      ts.isExportDeclaration(stmt) &&
      !stmt.exportClause &&
      stmt.moduleSpecifier &&
      ts.isStringLiteral(stmt.moduleSpecifier)
    ) {
      const reExportPath = resolveImportPath(
        stmt.moduleSpecifier.text,
        fileDir,
      );
      const sub = extractModule(reExportPath, emittedTypes);
      functions.push(...sub.functions);
      types.push(...sub.types);
    }
  }

  // Extract from this file
  for (const stmt of src.statements) {
    // Function declarations: `export declare function name(...): Type;`
    if (ts.isFunctionDeclaration(stmt) && stmt.name) {
      const modifiers = ts.getModifiers(stmt);
      const isExported = modifiers?.some(
        (m) => m.kind === ts.SyntaxKind.ExportKeyword,
      );
      if (!isExported) continue;

      const params = stmt.parameters.map((p) => paramToInfo(p, src));
      let returnType = typeToString(stmt.type, src);
      functions.push({ name: stmt.name.text, params, returnType });
    }

    // Variable declarations: `declare const list: () => string[], status: () => ...;`
    // These export multiple functions via `export { list, status, ... }`
    if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (!decl.type || !ts.isIdentifier(decl.name)) continue;
        // Each declaration could be a comma-separated group of const with function types
        // The pattern is: `declare const list: () => string[], status: () => ...;`
        // TypeScript parser creates one VariableDeclaration per name in `const a: T, b: T`
        const name = decl.name.text;
        const typeNode = decl.type;
        if (ts.isFunctionTypeNode(typeNode)) {
          const params = typeNode.parameters.map((p) => paramToInfo(p, src));
          const returnType = typeToString(typeNode.type, src);
          functions.push({ name, params, returnType });
        }
      }
    }

    // Interfaces
    if (ts.isInterfaceDeclaration(stmt)) {
      const modifiers = ts.getModifiers(stmt);
      const isExported = modifiers?.some(
        (m) => m.kind === ts.SyntaxKind.ExportKeyword,
      );
      if (!isExported) continue;
      const name = stmt.name.text;
      if (!emittedTypes.has(name)) {
        emittedTypes.add(name);
        types.push({ name, text: stmt.getText(src) });
      }
    }

    // Type aliases
    if (ts.isTypeAliasDeclaration(stmt)) {
      const modifiers = ts.getModifiers(stmt);
      const isExported = modifiers?.some(
        (m) => m.kind === ts.SyntaxKind.ExportKeyword,
      );
      if (!isExported) continue;
      const name = stmt.name.text;
      if (!emittedTypes.has(name)) {
        emittedTypes.add(name);
        types.push({ name, text: stmt.getText(src) });
      }
    }

    // Enums
    if (ts.isEnumDeclaration(stmt)) {
      const modifiers = ts.getModifiers(stmt);
      const isExported = modifiers?.some(
        (m) => m.kind === ts.SyntaxKind.ExportKeyword,
      );
      if (!isExported) continue;
      const name = stmt.name.text;
      if (!emittedTypes.has(name)) {
        emittedTypes.add(name);
        types.push({ name, text: stmt.getText(src) });
      }
    }
  }

  // Handle the `declare const a: () => T, b: () => U;` single-statement pattern
  // The TS parser actually splits `const a: T, b: U` into one VariableStatement with
  // multiple declarations in the declarationList. Let's re-check this is handled above.
  // Actually, the parser may create a single VariableDeclaration with the entire text.
  // Let's also handle the case where `const` has multiple declarators:
  for (const stmt of src.statements) {
    if (ts.isVariableStatement(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(decl.name)) continue;
        const name = decl.name.text;
        // Skip if already captured
        if (functions.some((f) => f.name === name)) continue;
        if (!decl.type) continue;
        if (ts.isFunctionTypeNode(decl.type)) {
          const params = decl.type.parameters.map((p) => paramToInfo(p, src));
          const returnType = typeToString(decl.type.type, src);
          functions.push({ name, params, returnType });
        }
      }
    }
  }

  // Also handle import + re-export type patterns like:
  // `import { type IntentOptions } from "../lib/intent.js";`
  // `export type { IntentOptions };`
  // We need to find the source and extract the type
  for (const stmt of src.statements) {
    if (
      ts.isExportDeclaration(stmt) &&
      stmt.exportClause &&
      ts.isNamedExports(stmt.exportClause) &&
      stmt.isTypeOnly
    ) {
      for (const el of stmt.exportClause.elements) {
        const exportedName = (el.name || el.propertyName)!.text;
        if (emittedTypes.has(exportedName)) continue;

        // Find the matching import
        let importPath: string | undefined;
        for (const s of src.statements) {
          if (
            ts.isImportDeclaration(s) &&
            s.moduleSpecifier &&
            ts.isStringLiteral(s.moduleSpecifier) &&
            s.importClause?.namedBindings &&
            ts.isNamedImports(s.importClause.namedBindings)
          ) {
            for (const binding of s.importClause.namedBindings.elements) {
              if (binding.name.text === exportedName) {
                importPath = resolveImportPath(s.moduleSpecifier.text, fileDir);
              }
            }
          }
        }

        // Also check re-export with module specifier: `export type { X } from "./y.js"`
        if (
          !importPath &&
          stmt.moduleSpecifier &&
          ts.isStringLiteral(stmt.moduleSpecifier)
        ) {
          importPath = resolveImportPath(stmt.moduleSpecifier.text, fileDir);
        }

        if (importPath && existsSync(importPath)) {
          const importedSrc = parseFile(importPath);
          for (const s of importedSrc.statements) {
            if (ts.isInterfaceDeclaration(s) && s.name.text === exportedName) {
              if (!emittedTypes.has(exportedName)) {
                emittedTypes.add(exportedName);
                types.push({
                  name: exportedName,
                  text: s.getText(importedSrc),
                });
              }
            }
            if (ts.isTypeAliasDeclaration(s) && s.name.text === exportedName) {
              if (!emittedTypes.has(exportedName)) {
                emittedTypes.add(exportedName);
                types.push({
                  name: exportedName,
                  text: s.getText(importedSrc),
                });
              }
            }
          }
        }
      }
    }
  }

  // Import type re-exports with rename: `export type { IntentOptions as BroadcastOptions };`
  for (const stmt of src.statements) {
    if (
      ts.isExportDeclaration(stmt) &&
      stmt.exportClause &&
      ts.isNamedExports(stmt.exportClause) &&
      stmt.isTypeOnly
    ) {
      for (const el of stmt.exportClause.elements) {
        if (!el.propertyName) continue; // no rename
        const originalName = el.propertyName.text;
        const exportedName = el.name.text;
        if (emittedTypes.has(exportedName)) continue;

        // Find the type under its original name in already-collected types
        const original = types.find((t) => t.name === originalName);
        if (original) {
          emittedTypes.add(exportedName);
          types.push({
            name: exportedName,
            text: original.text.replace(originalName, exportedName),
          });
        }
      }
    }
  }

  // Follow imports for types referenced in function signatures but not locally defined
  // e.g., `import type { PinInfo } from "@/common/pins.js"` used in return types
  const importMap = new Map<string, string>(); // typeName → resolved file path
  for (const stmt of src.statements) {
    if (
      ts.isImportDeclaration(stmt) &&
      stmt.moduleSpecifier &&
      ts.isStringLiteral(stmt.moduleSpecifier) &&
      stmt.importClause?.namedBindings &&
      ts.isNamedImports(stmt.importClause.namedBindings)
    ) {
      const resolvedPath = resolveImportPath(
        stmt.moduleSpecifier.text,
        fileDir,
      );
      for (const binding of stmt.importClause.namedBindings.elements) {
        const localName = binding.name.text;
        importMap.set(localName, resolvedPath);
      }
    }
  }

  // Collect all type names referenced in function signatures
  const referencedTypeNames = new Set<string>();
  for (const fn of functions) {
    const allStrings = [fn.returnType, ...fn.params.map((p) => p.type)];
    for (const s of allStrings) {
      // Extract identifiers that look like type references (PascalCase words)
      const matches = s.match(/\b[A-Z]\w+\b/g);
      if (matches) {
        for (const m of matches) referencedTypeNames.add(m);
      }
    }
  }

  // For referenced types not yet emitted, try to resolve from imports
  for (const typeName of referencedTypeNames) {
    if (emittedTypes.has(typeName)) continue;
    if (types.some((t) => t.name === typeName)) continue;

    const importFile = importMap.get(typeName);
    if (!importFile || !existsSync(importFile)) continue;

    const importedSrc = parseFile(importFile);
    for (const s of importedSrc.statements) {
      if (ts.isInterfaceDeclaration(s) && s.name.text === typeName) {
        emittedTypes.add(typeName);
        types.push({ name: typeName, text: s.getText(importedSrc) });
      }
      if (ts.isTypeAliasDeclaration(s) && s.name.text === typeName) {
        emittedTypes.add(typeName);
        types.push({ name: typeName, text: s.getText(importedSrc) });
      }
    }
  }

  return { functions, types };
}

interface NamespaceInfo {
  name: string;
  importPath: string; // resolved absolute path to .d.ts
  category: "common" | "fruity" | "droid";
}

function parseRouter(
  routerPath: string,
  platform: "fruity" | "droid",
): NamespaceInfo[] {
  const src = parseFile(routerPath);
  const routerDir = dirname(routerPath);
  const namespaces: NamespaceInfo[] = [];

  for (const stmt of src.statements) {
    if (
      ts.isImportDeclaration(stmt) &&
      stmt.importClause &&
      ts.isStringLiteral(stmt.moduleSpecifier)
    ) {
      const specifier = stmt.moduleSpecifier.text;
      const name =
        stmt.importClause.name?.text ??
        (stmt.importClause.namedBindings &&
        ts.isNamespaceImport(stmt.importClause.namedBindings)
          ? stmt.importClause.namedBindings.name.text
          : undefined);

      if (!name) continue;

      const resolvedPath = resolveImportPath(specifier, routerDir);
      let category: "common" | "fruity" | "droid";
      if (specifier.startsWith("@/common/")) {
        category = "common";
      } else if (name === "pins") {
        // pins is identical on both platforms, treat as common
        category = "common";
      } else {
        category = platform;
      }

      namespaces.push({ name, importPath: resolvedPath, category });
    }
  }

  return namespaces;
}

function unwrapReturn(returnType: string): string {
  const match = returnType.match(/^Promise<(.+)>$/s);
  if (match) return match[1];
  return returnType;
}

function referencesType(returnType: string, typeName: string): boolean {
  // Simple heuristic: check if typeName appears as a word boundary in the return type
  const re = new RegExp(
    `\\b${typeName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`,
  );
  return re.test(returnType);
}

function generateMarkdown(
  namespaces: Map<string, { filePath: string }>,
): string {
  const lines: string[] = [];
  const emittedTypes = new Set<string>();
  const shownTypes = new Set<string>();
  const sortedNames = [...namespaces.keys()].sort();

  for (const ns of sortedNames) {
    const { filePath } = namespaces.get(ns)!;
    const mod = extractModule(filePath, emittedTypes);

    if (mod.functions.length === 0) continue;

    lines.push(`## ${ns}`);
    lines.push("");

    for (const fn of mod.functions) {
      lines.push(`### ${ns}.${fn.name}`);
      lines.push("");

      // Invocation example
      const paramNames = fn.params.map((p) => p.name).join(", ");
      lines.push("```");
      lines.push(`invoke("${ns}", "${fn.name}", [${paramNames}])`);
      lines.push("```");
      lines.push("");

      // Parameter table
      if (fn.params.length > 0) {
        lines.push("| Param | Type |");
        lines.push("|-------|------|");
        for (const p of fn.params) {
          lines.push(`| ${p.name} | \`${p.type}\` |`);
        }
        lines.push("");
      }

      // Return type
      const rawReturn = fn.returnType;
      const displayReturn = unwrapReturn(rawReturn);
      lines.push(`Returns: \`${displayReturn}\``);
      lines.push("");

      // Show any referenced types (from return type and params), skip already shown
      const allTypeStrings = [displayReturn, ...fn.params.map((p) => p.type)];
      const referencedTypes = mod.types.filter(
        (t) =>
          !shownTypes.has(t.name) &&
          allTypeStrings.some((s) => referencesType(s, t.name)),
      );
      for (const t of referencedTypes) {
        shownTypes.add(t.name);
        lines.push("```typescript");
        lines.push(t.text);
        lines.push("```");
        lines.push("");
      }
    }
  }

  return lines.join("\n");
}

function main() {
  const fruityNs = parseRouter(
    resolve(AGENT_TYPES, "fruity/router.d.ts"),
    "fruity",
  );
  const droidNs = parseRouter(
    resolve(AGENT_TYPES, "droid/router.d.ts"),
    "droid",
  );

  // Deduplicate common namespaces (same namespace from both routers)
  const commonMap = new Map<string, { filePath: string }>();
  const fruityMap = new Map<string, { filePath: string }>();
  const droidMap = new Map<string, { filePath: string }>();

  for (const ns of fruityNs) {
    if (ns.category === "common") {
      commonMap.set(ns.name, { filePath: ns.importPath });
    } else {
      fruityMap.set(ns.name, { filePath: ns.importPath });
    }
  }

  for (const ns of droidNs) {
    if (ns.category === "common") {
      // Don't overwrite — same source files
      if (!commonMap.has(ns.name)) {
        commonMap.set(ns.name, { filePath: ns.importPath });
      }
    } else {
      droidMap.set(ns.name, { filePath: ns.importPath });
    }
  }

  const commonMd = generateMarkdown(commonMap);
  const fruityMd = generateMarkdown(fruityMap);
  const droidMd = generateMarkdown(droidMap);

  const outDir = resolve(import.meta.dirname!, "../skills");

  writeFileSync(resolve(outDir, "common.md"), commonMd);
  writeFileSync(resolve(outDir, "fruity.md"), fruityMd);
  writeFileSync(resolve(outDir, "droid.md"), droidMd);

  // Summary
  console.log(`common.md: ${commonMap.size} namespaces`);
  console.log(`fruity.md: ${fruityMap.size} namespaces`);
  console.log(`droid.md:  ${droidMap.size} namespaces`);
}

main();
