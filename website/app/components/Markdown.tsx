import { remark } from "remark";
import html from "remark-html";
import { visit } from "unist-util-visit";

const base = process.env.NEXT_PUBLIC_BASE_PATH || "";

function rebaseUrls() {
  return (tree: Parameters<typeof visit>[0]) => {
    if (!base) return;
    visit(tree, (node: { type: string; url?: string }) => {
      if ((node.type === "link" || node.type === "image") && node.url?.startsWith("/")) {
        node.url = base + node.url;
      }
    });
  };
}

export async function Markdown({ content }: { content: string }) {
  const result = await remark().use(rebaseUrls).use(html).process(content);
  return (
    <article
      className="prose"
      dangerouslySetInnerHTML={{ __html: result.toString() }}
    />
  );
}
