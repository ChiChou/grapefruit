import { DocsLayout } from "../components/DocsLayout";

export default function Layout({ children }: { children: React.ReactNode }) {
  return <DocsLayout langHref="/cn/docs" langLabel="中文">{children}</DocsLayout>;
}
