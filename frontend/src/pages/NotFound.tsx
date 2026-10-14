import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="mx-auto mt-20 max-w-md rounded-xl bg-surface p-8 text-center">
      <p className="text-4xl font-semibold tabular-nums text-ink-3">404</p>
      <h1 className="mt-2 text-lg font-semibold">Page not found</h1>
      <p className="mt-1 text-sm text-ink-2">That page doesn't exist or has moved.</p>
      <Link to="/" className="mt-5 inline-block rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white">
        Back to home
      </Link>
    </div>
  );
}
