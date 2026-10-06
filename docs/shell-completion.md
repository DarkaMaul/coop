# Shell completion

`coop` ships with both static and dynamic shell completion via `clap_complete`. Static completion handles subcommand and flag names; dynamic completion additionally fills in live values for instance names, image names, and profile names by reading `~/.coop`. `coop completions zsh` generates dynamic completion by default; the other shells generate static scripts.

## Generated completion scripts

Generate a script once and drop it where your shell looks for completions.

### bash

```sh
mkdir -p ~/.local/share/bash-completion/completions
coop completions bash > ~/.local/share/bash-completion/completions/coop
```

System-wide variant:

```sh
coop completions bash | sudo tee /etc/bash_completion.d/coop > /dev/null
```

### zsh

The generated script includes live VM, image, and profile names. The completion file must live on `$fpath`, configured before `compinit`. If you don't already have a directory for it:

```sh
mkdir -p ~/.zfunc
echo 'fpath=(~/.zfunc $fpath)' >> ~/.zshrc
echo 'autoload -Uz compinit && compinit' >> ~/.zshrc
coop completions zsh > ~/.zfunc/_coop
```

Regenerate `_coop` after upgrading coop so its completion protocol matches the installed binary. Alternatively, generate it on each shell startup by adding this line **after `compinit`** in `~/.zshrc`:

```sh
source <(coop completions zsh)
```

If you already use `source <(COMPLETE=zsh coop)`, that continues to work. Only one setup is needed.

### fish

```sh
coop completions fish > ~/.config/fish/completions/coop.fish
```

### PowerShell

```powershell
coop completions powershell | Out-String | Invoke-Expression
```

Add the same line to your `$PROFILE` to load it on every shell start.

### elvish

```sh
coop completions elvish > ~/.config/elvish/lib/coop-completion.elv
echo 'use coop-completion' >> ~/.config/elvish/rc.elv
```

Restart the shell (or `source` your rc) after the first install.

## Dynamic completion

Dynamic completion lets `coop` itself compute candidates on TAB — so `coop shell <TAB>` lists your running instances, `coop up --image <TAB>` lists existing images, and `coop setup --profile <TAB>` / `coop up --profile <TAB>` list builtin and custom profiles.

For shells other than zsh, add one line to your shell rc. Zsh's generated script already enables dynamic completion.

```sh
# bash
echo 'source <(COMPLETE=bash coop)' >> ~/.bashrc

# fish
echo 'source (COMPLETE=fish coop | psub)' >> ~/.config/fish/config.fish

# elvish
echo 'eval (COMPLETE=elvish coop | slurp)' >> ~/.config/elvish/rc.elv
```

Dynamic completion also handles subcommand and flag names. If both static and dynamic scripts are loaded, load the dynamic script last: the most recently registered handler takes precedence.

## What completes where

| Argument | Source |
|----------|--------|
| Running instance name (`shell`, `claude`, `claude-agents`, `codex`, `push`, `pull`, `exec`, `agent update`) | Running VMs in `~/.coop/instances/` |
| Stopped instance name (`start`) | Stopped VMs in `~/.coop/instances/` |
| Other VM arguments (`stop`, `destroy`, `status`, `logs`, `editor`, `resize`, `model`, and management commands) | All registered VMs in `~/.coop/instances/` |
| `--image` (`up`, `setup`, `start` compatibility flag), `images --delete` | `~/.coop/images/` |
| `--profile` (`setup`, `up`), `profiles show <name>` | builtin profiles plus `[profiles.*]` from `~/.coop/config.toml` |
