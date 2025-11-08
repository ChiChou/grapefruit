import { Link, Outlet } from "react-router";
import { DeviceList } from "./DeviceList";
import { MoonIcon, SunIcon } from "lucide-react";
import { Button } from "./ui/button";
import { useTheme } from "./theme-provider";
import logo from "../assets/logo.svg";

export function WelcomePage() {
  const { theme, setTheme } = useTheme();

  const toggleDarkMode = () => {
    setTheme(theme === "dark" ? "light" : "dark");
  };

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden sm:flex-row">
      <div className="flex w-full flex-col border-b border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-900 sm:h-full sm:w-64 sm:border-b-0 sm:border-r">
        <div className="mb-6 flex items-center justify-center gap-2 px-4">
          <Link to="/">
            <img src={logo} alt="Grapefruit Logo" className="h-10 w-40" />
          </Link>
        </div>
        <DeviceList />
        <footer className="mt-auto flex items-center pt-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleDarkMode}
            aria-label="Toggle dark mode"
          >
            {theme === "dark" ? (
              <SunIcon className="h-5 w-5" />
            ) : (
              <MoonIcon className="h-5 w-5" />
            )}
          </Button>
        </footer>
      </div>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
