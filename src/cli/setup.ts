import * as fs from "node:fs";
import * as path from "node:path";
import { parseArgs } from "node:util";

function findSkillsDir(): string {
  // In dev: skills/ is at repo root (../../ from src/cli/)
  // In compiled binary: assets are extracted, asset() resolves them
  // In npm dist: skills/ is at package root (../../ from dist/)
  // All cases: walk up from this file to find skills/
  let dir = import.meta.dirname ?? __dirname;
  for (let i = 0; i < 5; i++) {
    const candidate = path.join(dir, "skills");
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  return "";
}

function findSkills(skillsDir: string): Map<string, string> {
  const skills = new Map<string, string>();
  if (!skillsDir || !fs.existsSync(skillsDir)) return skills;
  for (const entry of fs.readdirSync(skillsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const skillFile = path.join(skillsDir, entry.name, "SKILL.md");
    if (fs.existsSync(skillFile)) {
      skills.set(entry.name, fs.readFileSync(skillFile, "utf-8"));
    }
  }
  return skills;
}

function writeSkill(targetDir: string, name: string, content: string) {
  const dir = path.join(targetDir, name);
  fs.mkdirSync(dir, { recursive: true });
  const dest = path.join(dir, "SKILL.md");
  fs.writeFileSync(dest, content, "utf-8");
  return dest;
}

export async function runSetup(argv: string[]) {
  const args = parseArgs({
    args: argv,
    options: {
      global: { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
    allowPositionals: true,
    strict: false,
  });

  if (args.values.help) {
    console.log(`
igf setup — Install Claude Code skills

Usage:
  igf setup [options]

Installs /igf and /audit skills for Claude Code into the current
project's .claude/skills/ directory.

Options:
  --global    Install to ~/.claude/skills/ (available in all projects)
  -h, --help  Show this help
`);
    process.exit(0);
  }

  const skillsDir = findSkillsDir();
  const skills = findSkills(skillsDir);
  if (skills.size === 0) {
    console.error("Error: No skills found. The igf installation may be incomplete.");
    process.exit(1);
  }

  const home = process.env.HOME || process.env.USERPROFILE || "";
  const targetDir = args.values.global
    ? path.join(home, ".claude", "skills")
    : path.join(process.cwd(), ".claude", "skills");

  const label = args.values.global ? "~/.claude/skills" : ".claude/skills";

  for (const [name, content] of skills) {
    const dest = writeSkill(targetDir, name, content);
    console.log(`  /${name} → ${dest}`);
  }

  console.log(`\n${skills.size} skill(s) installed to ${label}`);
  console.log("Use /igf and /audit in Claude Code.");
}
