# Test Scripts for Continuum Tunnel Validation

Scripts to validate PTY/tunnel behaviors. Run via the CLI:

```bash
# Run a script
continuum run test-scripts/echo-loop.sh

# Run interactively
continuum run -i test-scripts/interactive-cat.sh

# Attach to running task
continuum attach <task-id>

# Attach with stdin forwarding
continuum attach -i <task-id>
```

## Scripts

| Script | Purpose | How to Test |
|--------|---------|-------------|
| `echo-loop.sh` | Streaming output (tailing) | `continuum run` then `continuum show -t <id>` |
| `interactive-cat.sh` | Interactive stdin/stdout | `continuum run -i` or `attach -i` |
| `countdown.sh` | Finite streaming with exit | `continuum run`, watch completion |
| `mixed-output.sh` | Interleaved stdout/stderr | Verify both streams visible |
| `signal-handler.sh` | Ctrl+C handling | `attach -i`, send Ctrl+C |
| `exit-codes.sh` | Various exit statuses | Check task status after completion |
| `large-output.sh` | Buffer stress test | Verify no truncation |
| `env-test.sh` | Environment variable passing | `continuum run -e FOO=bar` |
| `prompt-loop.sh` | Interactive prompts | Full interactive session test |
| `slow-start.sh` | Delayed output | Test attach to "quiet" task |

## Quick Validation Checklist

```bash
# 1. Basic output
continuum run test-scripts/countdown.sh
continuum show -t <id>  # Should see countdown

# 2. Tailing
continuum run test-scripts/echo-loop.sh
continuum show -t <id>  # Should stream live output
continuum cancel <id>

# 3. Interactive
continuum run -i test-scripts/interactive-cat.sh
# Type some text, see it echoed back
# Press Ctrl+D to exit

# 4. Attach to running
continuum run test-scripts/echo-loop.sh
continuum attach <id>  # Watch output
# Press ~. to detach

# 5. Attach with input
continuum run test-scripts/prompt-loop.sh
continuum attach -i <id>
# Respond to prompts

# 6. Signal handling
continuum run -i test-scripts/signal-handler.sh
# Press Ctrl+C, should see "Caught SIGINT"
# Press Ctrl+C again to exit

# 7. Exit codes
continuum run test-scripts/exit-codes.sh 42
continuum show <id>  # Should show exit code 42
```
