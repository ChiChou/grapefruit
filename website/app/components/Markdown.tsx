import { remark } from "remark";
import html from "remark-html";

export async function Markdown({ content }: { content: string }) {
  const result = await remark().use(html).process(content);
  return (
    <article
      className="prose"
      dangerouslySetInnerHTML={{ __html: result.toString() }}
    />
  );
}
