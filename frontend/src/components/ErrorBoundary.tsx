import { Component, type ErrorInfo, type ReactNode } from "react";

/** Last line of defence: a rendering crash shows a calm message instead of a blank page. */
export default class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(_error: Error, _info: ErrorInfo) {
    /* details intentionally not shown to the user */
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div role="alert" className="mx-auto mt-24 max-w-md rounded-xl bg-surface p-8 text-center">
        <h1 className="text-lg font-semibold">Something went wrong</h1>
        <p className="mt-2 text-sm text-ink-2">The page couldn't be displayed. Reloading usually fixes it.</p>
        <button
          className="mt-5 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white"
          onClick={() => window.location.assign("/")}
        >
          Back to overview
        </button>
      </div>
    );
  }
}
