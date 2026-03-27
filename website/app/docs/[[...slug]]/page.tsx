import { notFound } from "next/navigation";
import { Markdown } from "@/app/components/Markdown";
import * as docs from "@/content/en/docs";

const pages = docs as Record<string, string>;

export async function generateStaticParams(): Promise<Array<{ slug: string[] }>> {
  return [{ slug: [] }, ...Object.keys(pages).filter(k => k !== "index").map(k => ({ slug: [k] }))];
}

export default async function Page({
  params,
}: {
  params: Promise<{ slug?: string[] }>;
}) {
  const { slug } = await params;
  const key = slug?.length ? slug[0] : "index";
  const content = pages[key];
  if (!content) notFound();
  return <Markdown content={content} />;
}
