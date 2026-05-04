# Public Launch Checklist

- README and Chinese README explain the project clearly.
- Examples cover read-only, write, financial, email, filesystem, shell, and poisoned tools.
- Tests pass with `pnpm test`.
- `pnpm typecheck` and `pnpm build` pass.
- Demo generates scan, policy, reports, and audit receipts.
- `.gitignore` excludes `node_modules`, `dist`, `reports`, `.capagate`, `.env`, logs, and coverage.
- No API keys or real secrets are committed.
- GitHub Action and CI workflow are present.
- License is MIT.
- Roadmap calls out Ed25519 receipts and optional LLM explanations as future work.
