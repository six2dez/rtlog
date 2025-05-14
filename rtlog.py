#!/usr/bin/env python3
"""
rtlog.py: A wrapper around macOS `script` to record zsh sessions for red team operations without modifying ~/.zshrc.

OVERVIEW:
  rtlog.py captures shell commands, metadata, and terminal output for red team auditing and VECTR integration. It spawns
  a logged zsh session, stores metadata (timestamp, user, command, TTP tag, etc.), and produces a transcript as evidence.
  No permanent shell config changes are needed, using a temporary ZDOTDIR.

USAGE:
  python3 rtlog.py <subcommand> [options]

SUBCOMMANDS:
  start       Launch a logged zsh session
  stop        Stop the active session
  status      Display active session details
  import      Convert commands.jsonl to VECTR JSON
  help        Show detailed help for a topic

EXAMPLES:
  # Start a session with a MITRE ATT&CK TTP name
  python3 rtlog.py start --outdir ~/rt_logs --name T1190_Exploit_Public_Facing_Application

  # Start without ANSI colors in logs
  python3 rtlog.py start --outdir ~/rt_logs --name T1190_Exploit --no-color

  # Check active session
  python3 rtlog.py status

  # Stop the session
  python3 rtlog.py stop

  # Import logs for VECTR
  python3 rtlog.py import -i ~/rt_logs/20250514T1430Z_macbook_operator_T1190_Exploit/commands.jsonl -O vectr_events.json

FEATURES:
  - No ~/.zshrc changes; uses temporary ZDOTDIR
  - Rich metadata: timestamp, duration, user, cwd, command, args, exit status, session ID, TTY, PPID, command hash, env, TTP tag
  - Full session transcript via `script` with dynamic names (e.g., 20250514T1430Z_T1190_Exploit.log)
  - Custom session directory naming (e.g., 20250514T1430Z_macbook_operator_T1190_Exploit)
  - Enhanced human-readable commands.log with ANSI colors and visual hierarchy
  - Files per session: commands.jsonl, commands.log, <timestamp>[_<TTP>].log, <timestamp>[_<TTP>].time, audit.log
  - VECTR-compatible JSON export
  - Secure file handling (0700 permissions)
  - Mitigates zsh plugin issues (Powerlevel10k, McFly) with temporary ZDOTDIR

DEPENDENCIES:
  - Required: Python 3, script, zsh (builtin on macOS)
  - Optional: jq (command escaping), bc (precise duration)
  Install jq: `brew install jq`
  Install bc: `brew install bc`

TROUBLESHOOTING:
  - Check ~/.rt_command_logger/<SESSION_DIR>/audit.log for errors
  - Ensure zsh is installed: `zsh --version`
  - Verify disk space for large transcript files
  - Powerlevel10k/McFly warnings are suppressed; set --verbose to confirm
  - Report issues to your red team lead or internal channel

VERSION: 1.1.5
LAST UPDATED: May 14, 2025
"""

import os
import sys
import argparse
import json
import shutil
import subprocess
import tempfile
import uuid
import getpass
import signal
import shlex
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

# Version
VERSION = "1.1.5"

# Default output directory
DEFAULT_OUTDIR = Path.home() / ".rt_command_logger"

# State file for active session
STATE_FILE = DEFAULT_OUTDIR / ".rtlog_state"

# ANSI color codes for commands.log
ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "yellow": "\033[33m",
    "green": "\033[32m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "magenta": "\033[35m"
}

# Zsh plugin content
ZSHRC_TEMPLATE = r"""
# RTLOG session zshrc
# Suppress Powerlevel10k instant prompt warning
typeset -g POWERLEVEL9K_INSTANT_PROMPT=quiet

# Set HISTFILE to avoid McFly errors
export HISTFILE="$HOME/.zsh_history"

# Source user's .zshrc
source $HOME/.zshrc

zmodload zsh/datetime

export RT_SESSION_DIR="{session_dir}"
export RT_SESSION_ID="{session_id}"
export RT_TTP_TAG="{ttp_tag}"
export RT_TRANSCRIPT_FILE="{transcript_file}"
export RT_USE_COLOR="{use_color}"
export RT_COMMAND_COUNT=0

autoload -Uz add-zsh-hook

rtlog_preexec() {{
    RTLOG_CMD=$(printf '%s' "$1" | jq -sRr @json 2>/dev/null || printf '%s' "$1" | sed 's/"/\\"/g')
    RTLOG_START=$EPOCHREALTIME
    ((RT_COMMAND_COUNT++))
}}

rtlog_precmd() {{
    local RT_END=$EPOCHREALTIME
    local DURATION
    if command -v bc >/dev/null 2>&1; then
        DURATION=$(printf "%.3f" "$(echo "$RT_END - $RTLOG_START" | bc -l 2>/dev/null)")
    else
        DURATION=$(printf "%.3f" "$(($RT_END - $RTLOG_START))")
    fi
    local TIMESTAMP=$(strftime "%Y-%m-%dT%H:%M:%SZ" $EPOCHSECONDS)
    local USER=$(whoami)
    local CWD=$(pwd)
    local EXIT_STATUS=$?
    local EXIT_DESC
    local EXIT_COLOR
    case $EXIT_STATUS in
        0) EXIT_DESC="Success"; EXIT_COLOR="${{RT_USE_COLOR:+\033[32m}}";;
        127) EXIT_DESC="Command not found"; EXIT_COLOR="${{RT_USE_COLOR:+\033[31m}}";;
        *) EXIT_DESC="Error (code $EXIT_STATUS)"; EXIT_COLOR="${{RT_USE_COLOR:+\033[31m}}";;
    esac
    local TTY=$(tty)
    local ARGS=$(printf '%s' "$1" | cut -d' ' -f2- 2>/dev/null || echo "")
    local ENV=$(env | grep -E '^(PATH|HOME|SHELL)=' | jq -sRr @json 2>/dev/null || env | grep -E '^(PATH|HOME|SHELL)=' | sed 's/"/\\"/g')
    local CMD_HASH=$(printf '%s' "$RTLOG_CMD" | shasum -a 256 | cut -d' ' -f1)
    # JSON metadata (no colors)
    printf '{{"timestamp":"%s","duration":%s,"user":"%s","cwd":"%s","command":%s,"args":"%s","exit_status":%s,"exit_desc":"%s","session_id":"%s","tty":"%s","ppid":"%s","command_hash":"%s","env":%s,"ttp_tag":"%s","transcript":"%s"}}\n' \
      "$TIMESTAMP" "$DURATION" "$USER" "$CWD" "$RTLOG_CMD" "$ARGS" "$EXIT_STATUS" "$EXIT_DESC" "$RT_SESSION_ID" "$TTY" "$PPID" "$CMD_HASH" "$ENV" "$RT_TTP_TAG" "$RT_TRANSCRIPT_FILE" \
      >> "$RT_SESSION_DIR/commands.jsonl" 2>> "$RT_SESSION_DIR/audit.log"
    # Human-readable log with colors
    {{
      if [[ -n "$RT_USE_COLOR" ]]; then
        printf "${{RT_USE_COLOR:+\033[35m\033[1m}}=== Command #%s ===${{RT_USE_COLOR:+\033[0m}}\n" "$RT_COMMAND_COUNT"
        printf "${{RT_USE_COLOR:+\033[33m}}Timestamp:${{RT_USE_COLOR:+\033[0m}} %s (Duration: %ss)\n" "$TIMESTAMP" "$DURATION"
        printf "${{RT_USE_COLOR:+\033[1m}}Command:  ${{RT_USE_COLOR:+\033[0m}}%s\n" "$(printf '%s' "$RTLOG_CMD" | jq -r . 2>/dev/null || printf '%s' "$RTLOG_CMD")"
        printf "Args:     %s\n" "$ARGS"
        printf "${{RT_USE_COLOR:+%s}}Exit:     %s (%s)${{RT_USE_COLOR:+\033[0m}}\n" "$EXIT_COLOR" "$EXIT_STATUS" "$EXIT_DESC"
        printf "${{RT_USE_COLOR:+\033[33m}}User@CWD: ${{RT_USE_COLOR:+\033[0m}}%s@%s\n" "$USER" "$CWD"
        printf "${{RT_USE_COLOR:+\033[36m}}TTP Tag:  ${{RT_USE_COLOR:+\033[0m}}%s\n" "$RT_TTP_TAG"
        printf "${{RT_USE_COLOR:+\033[2m}}Details:${{RT_USE_COLOR:+\033[0m}}\n"
        printf "${{RT_USE_COLOR:+\033[2m}}  TTY:    %s${{RT_USE_COLOR:+\033[0m}}\n" "$TTY"
        printf "${{RT_USE_COLOR:+\033[2m}}  PPID:   %s${{RT_USE_COLOR:+\033[0m}}\n" "$PPID"
        printf "${{RT_USE_COLOR:+\033[2m}}  Hash:   %s${{RT_USE_COLOR:+\033[0m}}\n" "$CMD_HASH"
        printf "${{RT_USE_COLOR:+\033[2m}}  Transcript: %s${{RT_USE_COLOR:+\033[0m}}\n" "$RT_TRANSCRIPT_FILE"
        printf "\n"
      else
        printf "=== Command #%s ===\n" "$RT_COMMAND_COUNT"
        printf "Timestamp: %s (Duration: %ss)\n" "$TIMESTAMP" "$DURATION"
        printf "Command:   %s\n" "$(printf '%s' "$RTLOG_CMD" | jq -r . 2>/dev/null || printf '%s' "$RTLOG_CMD")"
        printf "Args:      %s\n" "$ARGS"
        printf "Exit:      %s (%s)\n" "$EXIT_STATUS" "$EXIT_DESC"
        printf "User@CWD:  %s@%s\n" "$USER" "$CWD"
        printf "TTP Tag:   %s\n" "$RT_TTP_TAG"
        printf "Details:\n"
        printf "  TTY:     %s\n" "$TTY"
        printf "  PPID:    %s\n" "$PPID"
        printf "  Hash:    %s\n" "$CMD_HASH"
        printf "  Transcript: %s\n" "$RT_TRANSCRIPT_FILE"
        printf "\n"
      fi
    }} >> "$RT_SESSION_DIR/commands.log" 2>> "$RT_SESSION_DIR/audit.log"
}}

add-zsh-hook preexec rtlog_preexec
add-zsh-hook precmd rtlog_precmd

# Update prompt
PS1="[RTLOG:$RT_SESSION_ID] $PS1"
"""

def log_audit_event(session_dir: Path, event: str, details: Dict = None):
    """Log session events to audit.log."""
    audit_file = session_dir / 'audit.log'
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = {"timestamp": timestamp, "event": event, "details": details or {}}
    with open(audit_file, 'a', encoding='utf-8') as f:
        json.dump(entry, f)
        f.write('\n')
    os.chmod(audit_file, 0o600)

def sanitize_name(name: str) -> str:
    """Sanitize custom name for filesystem safety."""
    name = name.strip().replace(' ', '_').replace('/', '_').replace(':', '_')
    name = ''.join(c for c in name if c.isalnum() or c in ['_', '-'])
    if len(name) > 50:
        print(f"Warning: Name '{name}' is long (>50 chars). Truncating to avoid filesystem issues.")
        name = name[:50]
    return name

def start_session(outdir: Path, name: Optional[str], verbose: bool, no_color: bool):
    """Start a new logged zsh session with script."""
    if not shutil.which('script'):
        sys.exit("Error: `script` command not found.")
    if not shutil.which('zsh'):
        sys.exit("Error: `zsh` not found.")
    if not (Path.home() / '.zshrc').exists():
        print("Warning: ~/.zshrc not found.")

    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    hostname = os.uname().nodename
    user = getpass.getuser()
    name_part = f"_{sanitize_name(name)}" if name else ""
    session_dir = outdir / f"{now}_{hostname}_{user}{name_part}"
    try:
        session_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    except FileExistsError:
        sys.exit(f"Error: Session directory {session_dir} already exists.")

    log_audit_event(session_dir, "session_start", {"name": name or "none", "use_color": not no_color})

    for file in ['commands.jsonl', 'commands.log']:
        file_path = session_dir / file
        file_path.touch(mode=0o600)
        os.chmod(file_path, 0o600)

    transcript_filename = f"{now}{name_part}.log"
    timing_filename = f"{now}{name_part}.time"
    transcript = session_dir / transcript_filename
    timing = session_dir / timing_filename

    with tempfile.TemporaryDirectory(prefix="rtlog_", dir=Path.home()) as temp_zd:
        temp_zd_path = Path(temp_zd)
        session_id = str(uuid.uuid4())
        ttp_tag = name or "none"
        zshrc = ZSHRC_TEMPLATE.format(
            session_dir=session_dir,
            session_id=session_id,
            ttp_tag=ttp_tag,
            transcript_file=transcript,
            use_color="" if no_color else "1"
        )
        zshrc_path = temp_zd_path / '.zshrc'
        with open(zshrc_path, 'w', encoding='utf-8') as f:
            f.write(zshrc)
        os.chmod(zshrc_path, 0o600)

        STATE_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            f.write(f"{session_dir}\n{session_id}\n{os.getpid()}")
        os.chmod(STATE_FILE, 0o600)

        if verbose:
            print(f"Session directory: {session_dir}")
            print(f"Session ID: {session_id}")
            print(f"TTP Tag: {ttp_tag}")
            print(f"Transcript: {transcript}")
            print(f"Timing file: {timing}")
            print(f"ZDOTDIR: {temp_zd_path}")
            print(f"ANSI colors in commands.log: {'disabled' if no_color else 'enabled'}")
            print("Powerlevel10k: Instant prompt warnings suppressed with POWERLEVEL9K_INSTANT_PROMPT=quiet")
            print("McFly: HISTFILE set to ~/.zsh_history to avoid history errors")

        print(f"Starting logged session in: {session_dir} (Session ID: {session_id})")
        print("Type 'exit', Ctrl-D, or run 'python3 rtlog.py stop' to end the session.")

        env = {k: v for k, v in os.environ.items() if not k.startswith(('API_', 'TOKEN_'))}
        env['ZDOTDIR'] = str(temp_zd_path)
        cmd = ['script', '-q', '-t', str(timing), str(transcript), 'zsh', '-i']
        try:
            subprocess.call(cmd, env=env)
        except subprocess.SubprocessError as e:
            sys.exit(f"Error running script session: {e}")
        except KeyboardInterrupt:
            print("\nSession interrupted.")
        finally:
            log_audit_event(session_dir, "session_end", {"transcript": str(transcript), "timing": str(timing)})
            if STATE_FILE.exists():
                STATE_FILE.unlink()
            print(f"Session ended. Logs in: {session_dir}")

def stop_session():
    """Stop the active session."""
    if not STATE_FILE.exists():
        print("No active session found.")
        return

    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            session_dir, session_id, pid = f.read().strip().split('\n')
        session_dir = Path(session_dir)
        try:
            os.kill(int(pid), signal.SIGTERM)
            time.sleep(0.1)
        except ProcessLookupError:
            pass
        if STATE_FILE.exists():
            STATE_FILE.unlink()
        log_audit_event(session_dir, "session_stop", {"session_id": session_id})
        print(f"Stopped session: {session_dir} (Session ID: {session_id})")
    except Exception as e:
        print(f"Error stopping session: {e}")

def status_session():
    """Display status of the active session."""
    if not STATE_FILE.exists():
        print("No active session.")
        return

    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            session_dir, session_id, pid = f.read().strip().split('\n')
        print(f"Active session:")
        print(f"  Directory: {session_dir}")
        print(f"  Session ID: {session_id}")
        print(f"  PID: {pid}")
    except Exception as e:
        print(f"Error checking status: {e}")

def import_vectr(input_path: Path, output_path: Path, template: Optional[Path]):
    """Convert commands.jsonl to VECTR-compatible JSON."""
    if not input_path.exists():
        sys.exit(f"Error: Input file {input_path} does not exist.")
    if not input_path.is_file():
        sys.exit(f"Error: {input_path} is not a file.")

    events = []
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        event = json.loads(line)
                        if template:
                            event = {"mapped": event}
                        events.append(event)
                    except json.JSONDecodeError as e:
                        print(f"Warning: Skipping malformed JSON line: {e}")
    except IOError as e:
        sys.exit(f"Error reading {input_path}: {e}")

    vectr = {'events': events}
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(vectr, f, indent=2)
        os.chmod(output_path, 0o600)
        print(f"Exported {len(events)} events to {output_path}.")
    except IOError as e:
        sys.exit(f"Error writing {output_path}: {e}")

def show_help(topic: str):
    """Display detailed help for a topic."""
    help_texts = {
        "all": """
rtlog.py Help - Red Team Session Logger

OVERVIEW:
  rtlog.py captures zsh sessions for red team operations, logging commands, metadata, and terminal output without modifying ~/.zshrc. It supports VECTR integration and custom session naming for MITRE ATT&CK TTPs.

SUBCOMMANDS:
  start [--outdir DIR] [--name NAME] [--verbose] [--no-color]
    Launch a logged zsh session.
    Options:
      --outdir, -o DIR    Output directory (default: ~/.rt_command_logger)
      --name, -n NAME     Custom name, e.g., T1190_Exploit (optional)
      --verbose, -v       Show detailed output
      --no-color          Disable ANSI colors in commands.log
    Example:
      python3 rtlog.py start --outdir ~/rt_logs --name T1190_Exploit_Public_Facing_Application

  stop
    Stop the active session.
    Example:
      python3 rtlog.py stop

  status
    Show active session details (directory, session ID, PID).
    Example:
      python3 rtlog.py status

  import --input FILE --output FILE [--template TEMPLATE]
    Convert commands.jsonl to VECTR JSON.
    Options:
      --input, -i FILE    Path to commands.jsonl
      --output, -O FILE   Output VECTR JSON file
      --template, -t FILE Custom VECTR template (optional)
    Example:
      python3 rtlog.py import -i ~/rt_logs/20250514T1430Z_macbook_operator_T1190_Exploit/commands.jsonl -O vectr_events.json

  help [--topic start|import|all]
    Show help for a topic (default: all).
    Example:
      python3 rtlog.py help --topic start

FILES PRODUCED:
  - commands.jsonl: JSON Lines metadata (timestamp, command, TTP tag, etc.)
  - commands.log: Human-readable summary with ANSI colors
  - <timestamp>[_<TTP>].log: Terminal transcript (e.g., 20250514T1430Z_T1190_Exploit.log)
  - <timestamp>[_<TTP>].time: Timing data for replay
  - audit.log: Session start/stop events

TROUBLESHOOTING:
  - Check ~/.rt_command_logger/<SESSION_DIR>/audit.log for errors
  - Ensure zsh is installed: `zsh --version`
  - Verify disk space: `df -h`
  - Powerlevel10k/McFly warnings are suppressed; set --verbose to confirm
  - Install optional dependencies: `brew install jq bc`
  - Report issues to your red team lead

VERSION: 1.1.5
LAST UPDATED: May 14, 2025
        """,
        "start": """
rtlog.py start - Launch a Logged Zsh Session

PURPOSE:
  Starts a new zsh session with logging enabled, capturing commands, metadata, and terminal output. Uses `script` for transcripts and zsh hooks for metadata, stored in a session directory.

OPTIONS:
  --outdir, -o DIR    Output directory (default: ~/.rt_command_logger)
  --name, -n NAME     Custom name, e.g., MITRE ATT&CK TTP like T1190_Exploit (optional)
  --verbose, -v       Show detailed output for debugging
  --no-color          Disable ANSI colors in commands.log

EXAMPLES:
  # Start a session for a web exploit TTP
  python3 rtlog.py start --outdir ~/rt_logs --name T1190_Exploit_Public_Facing_Application

  # Start without colors
  python3 rtlog.py start --outdir ~/rt_logs --name T1190_Exploit --no-color

NOTES:
  - Session directory: <outdir>/<timestamp>_<hostname>_<user>[_<name>]
  - Transcript file: <timestamp>[_<name>].log (e.g., 20250514T1430Z_T1190_Exploit.log)
  - commands.log uses ANSI colors for readability (disable with --no-color)
  - Powerlevel10k and McFly warnings are suppressed; use --verbose to confirm
  - Type 'exit' or 'python3 rtlog.py stop' to end
  - Check ~/.rt_command_logger/<SESSION_DIR>/audit.log for errors
        """,
        "import": """
rtlog.py import - Convert Logs to VECTR JSON

PURPOSE:
  Converts a session's commands.jsonl file to a VECTR-compatible JSON file for importing attack evidence.

OPTIONS:
  --input, -i FILE    Path to commands.jsonl from a session
  --output, -O FILE   Output path for VECTR JSON
  --template, -t FILE Custom VECTR template (optional, future use)

EXAMPLES:
  # Import logs from a session
  python3 rtlog.py import -i ~/rt_logs/20250514T1430Z_macbook_operator_T1190_Exploit/commands.jsonl -O vectr_events.json

  # Use with a custom template (future)
  python3 rtlog.py import -i ~/rt_logs/<SESSION_DIR>/commands.jsonl -O vectr_events.json -t vectr_template.json

NOTES:
  - Output JSON contains all command metadata (timestamp, command, TTP tag, etc.)
  - Transcript referenced in metadata: <timestamp>[_<TTP>].log
  - Check input file path if errors occur
  - Ensure output directory is writable
        """
    }
    print(help_texts.get(topic, help_texts["all"]).strip())

def main():
    parser = argparse.ArgumentParser(
        description='RT logging wrapper for red team operations using macOS script.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands: start, stop, status, import, help
Use `python3 rtlog.py help` for details or `python3 rtlog.py help --topic <start|import>` for specific guides.

Examples:
  python3 rtlog.py start --outdir ~/rt_logs --name T1190_Exploit
  python3 rtlog.py import -i ~/rt_logs/<SESSION_DIR>/commands.jsonl -O vectr_events.json
"""
    )
    parser.add_argument('--version', action='version', version=f'rtlog.py {VERSION}')
    sub = parser.add_subparsers(dest='command', required=True, help='Subcommands')

    parser_start = sub.add_parser('start', help='Launch a logged zsh session')
    parser_start.add_argument('--outdir', '-o', type=Path, default=DEFAULT_OUTDIR,
                              help='Base directory for session logs (default: ~/.rt_command_logger)')
    parser_start.add_argument('--name', '-n', type=str,
                              help='Custom name for session, e.g., MITRE ATT&CK TTP like T1190_Exploit')
    parser_start.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser_start.add_argument('--no-color', action='store_true', help='Disable ANSI colors in commands.log')

    parser_stop = sub.add_parser('stop', help='Stop the active session')

    parser_status = sub.add_parser('status', help='Display active session status')

    parser_imp = sub.add_parser('import', help='Convert commands.jsonl to VECTR JSON')
    parser_imp.add_argument('--input', '-i', type=Path, required=True,
                            help='Path to commands.jsonl')
    parser_imp.add_argument('--output', '-O', type=Path, required=True,
                            help='Output path for VECTR JSON')
    parser_imp.add_argument('--template', '-t', type=Path,
                            help='Custom VECTR JSON template (optional)')

    parser_help = sub.add_parser('help', help='Show detailed help')
    parser_help.add_argument('--topic', type=str, choices=['start', 'import', 'all'], default='all',
                             help='Help topic: start, import, or all')

    args = parser.parse_args()
    if args.command == 'start':
        start_session(args.outdir, args.name, args.verbose, args.no_color)
    elif args.command == 'stop':
        stop_session()
    elif args.command == 'status':
        status_session()
    elif args.command == 'import':
        import_vectr(args.input, args.output, args.template)
    elif args.command == 'help':
        show_help(args.topic)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()