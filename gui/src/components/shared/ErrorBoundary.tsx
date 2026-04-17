import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ErrorBoundary]", error, info.componentStack);
  }

  reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    if (this.props.fallback) return this.props.fallback;

    return (
      <div className="flex h-full w-full flex-col items-center justify-center gap-4 p-8 text-center">
        <AlertTriangle className="h-10 w-10 text-destructive" />
        <div>
          <p className="font-semibold text-destructive">Something went wrong</p>
          <p className="mt-1 font-mono text-xs text-muted-foreground">{error.message}</p>
        </div>
        <button
          onClick={this.reset}
          className="flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
        >
          <RotateCcw className="h-3.5 w-3.5" />
          Try again
        </button>
      </div>
    );
  }
}
