# rtlog - Red Team Session Logger

`rtlog` is a Python-based tool that wraps the macOS `script` command to record zsh sessions for red team operations, capturing commands, metadata, and terminal output without modifying `~/.zshrc`. It generates structured logs and transcripts for auditing and integration with VECTR, supporting MITRE ATT&CK TTP naming and secure, isolated session management.

## Features
- **No Shell Config Changes**: Uses a temporary `ZDOTDIR` to avoid modifying `~/.zshrc`.
- **Rich Metadata**: Logs timestamp, duration, user, cwd, command, args, exit status, session ID, TTY, PPID, command hash, environment, and TTP tag.
- **Dynamic Transcript Names**: Saves session output as `<timestamp>[_<TTP>].log` (e.g., `20250514T1430Z_T1190_Exploit.log`).
- **Enhanced Human-Readable Logs**: Formatted `commands.log` with ANSI colors, command numbering, and visual hierarchy.
- **VECTR Integration**: Exports `commands.jsonl` to VECTR-compatible JSON for attack evidence.
- **Secure File Handling**: Sets 0700 permissions on all output files.
- **Zsh Plugin Compatibility**: Suppresses Powerlevel10k and McFly warnings for clean output.
- **Custom Session Naming**: Supports TTP-based naming (e.g., `T1190_Exploit_Public_Facing_Application`).

## Installation

### Prerequisites
- **macOS** with:
  - Python 3.6+ (`python3 --version`)
  - `zsh` (built-in, verify: `zsh --version`)
  - `script` (built-in, verify: `which script`)
- **Optional** (for enhanced features):
  - `jq` (command escaping): `brew install jq`
  - `bc` (precise duration): `brew install bc`

### Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd rtlog
   ```
2. Install the script:
   ```bash
   mkdir -p ~/bin
   cp rtlog.py ~/bin/rtlog
   chmod +x ~/bin/rtlog
   ```
3. Add `~/bin` to `PATH` (if not already):
   ```bash
   echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc
   source ~/.zshrc
   ```
4. Verify installation:
   ```bash
   rtlog --version
   ```
   Expected output: `rtlog.py 1.1.5`

## Usage
Run `rtlog` with a subcommand to manage logging sessions.

### Subcommands
- `start [--outdir DIR] [--name NAME] [--verbose] [--no-color]`: Launch a logged zsh session.
- `stop`: Stop the active session.
- `status`: Display active session details.
- `import --input FILE --output FILE [--template TEMPLATE]`: Convert `commands.jsonl` to VECTR JSON.
- `help [--topic start|import|all]`: Show detailed help.

### Examples
1. **Start a session** with a TTP name:
   ```bash
   rtlog start --outdir ~/rt_logs --name T1190_Exploit_Public_Facing_Application
   ```
   - Creates a session directory: `~/rt_logs/20250514T1430Z_<hostname>_<user>_T1190_Exploit`
   - Logs commands to `commands.jsonl` and `commands.log`
   - Saves transcript to `20250514T1430Z_T1190_Exploit.log`
   - Exit with `exit` or `Ctrl-D`.

2. **Start with verbose output** and no colors:
   ```bash
   rtlog start --outdir ~/rt_logs --name T1234 --verbose --no-color
   ```

3. **Check session status**:
   ```bash
   rtlog status
   ```

4. **Stop the session**:
   ```bash
   rtlog stop
   ```

5. **Import logs for VECTR**:
   ```bash
   rtlog import -i ~/rt_logs/20250514T1430Z_<hostname>_<user>_T1190_Exploit/commands.jsonl -O vectr_events.json
   ```

### Sample Workflow
```bash
rtlog start --outdir ~/rt_logs --name T1190_Exploit
# In the logged session:
ls -lahtr
ffuf -w /path/to/wordlist.txt -u https://example.com/FUZZ -mc 200
exit
rtlog import -i ~/rt_logs/20250514T1430Z_<hostname>_<user>_T1190_Exploit/commands.jsonl -O vectr_events.json
```

## Output Files
Each session creates a directory (e.g., `~/rt_logs/20250514T1430Z_<hostname>_<user>_T1190_Exploit`) with:
- `commands.jsonl`: JSON Lines metadata (timestamp, command, TTP tag, etc.).
- `commands.log`: Human-readable summary with ANSI colors and command numbering.
- `<timestamp>[_<TTP>].log`: Terminal transcript (e.g., `20250514T1430Z_T1190_Exploit.log`).
- `<timestamp>[_<TTP>].time`: Timing data for replay.
- `audit.log`: Session start/stop events and errors.

### Example `commands.log`
```text
=== Command #1 ===
Timestamp: 2025-05-14T14:30:15Z (Duration: 0.123s)
Command:   ls -lahtr
Args:      -lahtr
Exit:      0 (Success)
User@CWD:  operator@/Users/operator/red_team
TTP Tag:   T1190_Exploit
Details:
  TTY:     /dev/ttys001
  PPID:    12345
  Hash:    a1b2c3d4e5f6...
  Transcript: /Users/operator/rt_logs/20250514T1430Z_<hostname>_operator_T1190_Exploit/20250514T1430Z_T1190_Exploit.log
```

## Troubleshooting
- **No session logs**:
  - Check `audit.log`: `cat ~/rt_logs/<SESSION_DIR>/audit.log`.
  - Run with `--verbose`: `rtlog start --verbose`.
- **Zsh plugin warnings** (Powerlevel10k, McFly):
  - Suppressed by default; verify with `--verbose`.
  - Ensure `zsh --version` is 5.8+.
- **Disk space**:
  - Check: `df -h`.
  - Clear old logs: `rm -rf ~/rt_logs/*`.
- **Dependencies**:
  - Install `jq` and `bc`: `brew install jq bc`.
- **Issues**:
  - Report to your red team lead or open an issue on the repository.

## Contributing
1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Commit changes: `git commit -m "Add feature-name"`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

## License
MIT License. See [LICENSE](LICENSE) for details.