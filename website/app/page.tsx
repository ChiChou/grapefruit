import { Landing } from "./components/Landing";
import { en } from "./i18n";

export default function Home() {
  return <Landing t={en} langHref="/cn" />;
}
