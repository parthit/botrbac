"""Terminal: protected files can't be reached by moving their folder, globs, split quotes,
`cd`, or spelling the switch-off markers differently."""

import pytest

from botrbac_cli.protect import refusal


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text("{}")
    (home / ".codex").mkdir()
    (home / ".codex" / "hooks.json").write_text("{}")
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / "src").mkdir()
    (proj / "src" / "app.py").write_text("")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("BOTRBAC_HOME", str(home / ".config" / "botrbac"))
    monkeypatch.chdir(proj)
    return tmp_path


@pytest.mark.parametrize(
    "command",
    [
        # The folder that holds a protected file.
        "rm -rf ~/.claude",
        "mv ~/.claude ~/.c2",
        "mv ~/.codex /tmp/x",
        "mv .claude .c",
        "rm -r $HOME/.config",
        "cd ~ && rm -rf .claude",
        "rm -rf ~",
        "rm -rf /*",
        "rm -rf ~/.*",
        # Globs.
        "sed -i /botrbac/d ~/.claude/setting*",
        "sed -i /botrbac/d ~/.claude/settings.js?n",
        "sed -i /botrbac/d ~/.cl*/settings.json",
        "rm -rf ~/.c[l]aude",
        "cp -r other ~/.claude",
        "chmod 000 ~/.claude",
        "cp /dev/null ~/.claude/settings.local.j*",
        # Quotes split the name.
        "sed -i /botrbac/d ~/.claude/'settings'.json",
        'sed -i /botrbac/d ~/.claude/sett""ings.json',
        # `cd` first, then a relative path.
        "cd ~/.claude && sed -i /botrbac/d settings.json",
        "cd ~; cd .codex; rm hooks.json",
        "bash -c 'cd ~/.claude && rm settings.json'",
        # The switch-off markers, written differently.
        "echo '{\"disableAll''Hooks\":true}' > x.json",
        "botrbac  hooks  remove claude-code --user",
        "botrbac 'hooks' remove claude-code",
        # The login, even only to read it.
        "cat ~/.config/botrbac/cred*",
    ],
)
def test_bash_ways_round_the_protection_are_refused(command) -> None:
    assert refusal("Bash", {"command": command}), command


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("mcp__fs__move_file", {"source": "~/.claude", "destination": "~/old"}),
        ("fs/delete_directory", {"path": "~/.codex"}),
        ("Write", {"file_path": "~/.claude/sett*.json", "content": "{}"}),
    ],
)
def test_other_tools_cannot_move_the_folder(tool, tool_input) -> None:
    assert refusal(tool, tool_input)


@pytest.mark.parametrize(
    "command",
    [
        "ls ~/.claude",
        "ls -la ~/.claude ~/.codex",
        "cd ~/.claude && ls",
        "find ~/.claude -name '*.md'",
        "grep -r botrbac ~/.claude",
        'git commit -m "Ignore .claude locally"',
        "git commit -m .claude",
        "git add . && git status",
        "rm -rf build dist *.egg-info",
        "rm src/*.pyc",
        "sed -i s/a/b/ src/app.py",
        "cd src && sed -i s/a/b/ app.py",
        "mv src/app.py src/main.py",
        "uv run pytest -q",
        "mkdir -p .claude/commands && touch .claude/commands/x.md",
        "cp -r ~/.claude ~/claude-backup",
        "cp -r . ../copy && find . -name '*.pyc' -delete",
        "git checkout -- . && rm -rf node_modules",
        "echo 'it is not here' | tee notes.txt",
        "python -c 'print(1)'",
        "echo unbalanced 'quote",
    ],
)
def test_ordinary_commands_pass(command) -> None:
    assert refusal("Bash", {"command": command}) is None, command


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Read", {"file_path": "~/.claude/settings.json"}),
        ("Grep", {"pattern": "x", "path": "~/.claude"}),
        ("Glob", {"pattern": "~/.claude/*"}),
        ("fs/list_directory", {"path": "~/.claude"}),
        ("Edit", {"file_path": "src/app.py", "old_string": "a", "new_string": "see ~/.claude"}),
        ("Write", {"file_path": "docs/x.md", "content": "Run `rm -rf ~/.claude` to reset."}),
    ],
)
def test_reading_and_ordinary_edits_pass(tool, tool_input) -> None:
    assert refusal(tool, tool_input) is None


def test_reading_settings_through_the_shell_is_still_refused() -> None:
    # Unchanged: a shell command that names a protected file is refused, even `cat`,
    # because the hook cannot tell what the command does with it.
    assert refusal("Bash", {"command": "cat ~/.claude/settings.json"})
