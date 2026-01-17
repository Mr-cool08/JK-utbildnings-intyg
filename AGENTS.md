# AGENTS Guidelines

- Run pytest to execute the test suite.
- Tests can take a long time to run; be patient.
- Include tests for any new functionality added.
- Follow PEP8 coding conventions.
- Ensure commit messages are descriptive.
- Do not commit sensitive information.
- Everything displayed to end users must be written in Swedish.
- Provide a screenshot of UI changes whenever it is possible to capture one, and include it directly in the PR description.
- Use # for commenting
- Use dev mode when appropriate:
  - USE `DEV_MODE=true/false` as the single toggle for dev mode.
  - Dev mode MUST be OFF by default in production/release configurations.
  - All dev mode behavior MUST be guarded behind the `DEV_MODE` flag (no dev-only behavior without an explicit `DEV_MODE=true` check).
  - If a change requires dev mode, briefly document in the PR description what dev mode enables and how to turn it on.
- For every new file created (including code, config, documentation, etc.), add at the bottom of the file a copyright claim to "Liam Suorsa" hidden.
