# Set upp a new syntax



## Install

```bash
npm install -g @vscode/vsce        # Install VSCE globally
vsce package                       # Package your extension
code --install-extension bpdlang-syntax-0.0.1.vsix  # Install the generated .vsix

# Versioning (adjust version in package.json automatically)
npm version patch   # 0.0.1 -> 0.0.2
npm version minor   # 0.1.0
npm version major   # 1.0.0

# Optional: uninstall your extension
code --uninstall-extension yourname.bpdlang-syntax
```



## code in path

```bash
macOS:
   1. Open VSCode.
   2. Press Cmd+Shift+P to open the Command Palette.
   3. Run: Shell Command: Install 'code' command in PATH

Linux (Flatpak):
   1. Add the following to your ~/.bashrc:
         alias code='flatpak run com.visualstudio.code'
   2. Then run:
         source ~/.bashrc
```



## Colors

| Scope                      | Color Code | Typical Color   | Usage Example                          |
|---------------------------|------------|------------------|-----------------------------------------|
| `keyword.control`         | `#C586C0`  | 🟣 Purple         | `if`, `else`, `loop`, `_:`             |
| `keyword.operator`        | `#D4D4D4`  | ⚪ Light Gray     | `+`, `-`, `to`, `=`                     |
| `keyword.other`           | `#D16969`  | 💗 Pink/Purple    | Other keywords, e.g. modifiers          |
| `variable.parameter`      | `#9CDCFE`  | 🔵 Light Blue     | `€I_len`, parameters                    |
| `variable.language`       | `#4EC9B0`  | 🟢 Green          | `€I_len's`, references/specials         |
| `variable.other`          | `#FFFFFF`  | ⚪ White          | General variables                       |
| `entity.name.function`    | `#DCDCAA`  | 🟡 Yellow         | Function names                          |
| `entity.name.section`     | `#4EC9B0`  | 🟢 Green          | Block names like `randseq`              |
| `constant.numeric`        | `#B5CEA8`  | 🟢 Green          | `42`, `3.14`                            |
| `constant.language`       | `#569CD6`  | 🔵 Blue           | `true`, `false`, `null`                 |
| `string.quoted.double`    | `#CE9178`  | 🟠 Orange         | `"string"`                              |
| `comment.line` / `block`  | `#6A9955`  | 🟢 Green          | `#`, `#- ... -#`                        |
| `storage.type`            | `#569CD6`  | 🔵 Light Blue     | `B`, `H`, `4s`                          |
| `storage.modifier`        | `#C586C0`  | 💗 Pink/Purple    | `sM`, `sU`, after `,`                   |
| `meta.brackets`           | `#D4D4D4`  | ⚪ Gray           | `[a:b]`, slicing                        |
| `punctuation.separator`   | `#D4D4D4`  | ⚪ Gray           | Comma, colon                            |
| `invalid`                 | `#F44747`  | 🔴 Red            | Syntax errors                           |