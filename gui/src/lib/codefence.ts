/**
 * Streaming parser for markdown code fences.
 * Extracts the language tag and strips opening/closing fences.
 *
 * State machine:
 *   BEFORE  → accumulating text before opening ```
 *   LANG    → reading the language tag after ```
 *   CODE    → inside the code block, passing through
 *   DONE    → closing ``` found, ignore rest
 */

const BEFORE = 0;
const LANG = 1;
const CODE = 2;
const DONE = 3;

/** Normalize LLM fence tags to Monaco editor language IDs. */
const LANG_MAP: Record<string, string> = {
  "c++": "cpp",
  "objc": "objective-c",
  "objectivec": "objective-c",
  "obj-c": "objective-c",
  "js": "javascript",
  "ts": "typescript",
};

function normLang(raw: string): string {
  const lower = raw.toLowerCase();
  return LANG_MAP[lower] ?? lower;
}

export class Parser {
  private state = BEFORE;
  private buf = "";
  private backtickCount = 0;

  /** Monaco-compatible language ID (normalized). */
  lang = "";
  code = "";

  /** Feed a new chunk of streamed text. Returns the code accumulated so far. */
  push(chunk: string): string {
    for (let i = 0; i < chunk.length; i++) {
      const ch = chunk[i];

      switch (this.state) {
        case BEFORE:
          if (ch === "`") {
            this.backtickCount++;
            if (this.backtickCount >= 3) {
              this.state = LANG;
              this.backtickCount = 0;
            }
          } else {
            this.backtickCount = 0;
          }
          break;

        case LANG:
          if (ch === "\n") {
            this.lang = normLang(this.buf.trim());
            this.buf = "";
            this.state = CODE;
          } else {
            this.buf += ch;
          }
          break;

        case CODE:
          if (ch === "`") {
            this.backtickCount++;
            if (this.backtickCount >= 3) {
              this.code = this.code.slice(0, -(this.backtickCount - 1));
              this.state = DONE;
            }
          } else {
            this.backtickCount = 0;
          }
          if (this.state === CODE) {
            this.code += ch;
          }
          break;

        case DONE:
          break;
      }
    }

    return this.code;
  }

  /** True if the opening fence has been parsed (language is known). */
  get started(): boolean {
    return this.state === CODE || this.state === DONE;
  }
}
