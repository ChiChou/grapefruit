import { DocsLayout } from "../../components/DocsLayout";

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <DocsLayout prefix="/cn" langHref="/docs" langLabel="English">
      {children}
    </DocsLayout>
  );
}
