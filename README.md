# GitHub Privacy Push Guard Skill

GitHubへpushする前に、secret・個人情報・ローカル環境情報・危険ファイルを検査し、公開事故を防ぐためのSkillパッケージです。

## 内容

```text
github-privacy-push-guard/
  SKILL.md                         # ChatGPT skill本体
  tools/privacy_guard.py            # 標準ライブラリのみで動くローカル検査スクリプト
  examples/.pre-commit-config.yaml  # pre-commit設定例
  examples/gitleaks.toml            # gitleaks設定例
  examples/pre-push                 # pre-push hook例
  examples/privacy-guard-allowlist  # 誤検知を限定的に許可する例
  .github/workflows/privacy-guard.yml
  install.sh
```

## 開発環境構築

```bash
python3 --version
git --version
python3 -m pip install --user pre-commit

# 推奨: 公式手順またはパッケージマネージャでインストール
gitleaks version
trufflehog --version
```

## 導入

```bash
# リポジトリ直下で実行
cp -r github-privacy-push-guard/tools ./tools
cp github-privacy-push-guard/examples/.pre-commit-config.yaml ./.pre-commit-config.yaml
cp github-privacy-push-guard/examples/gitleaks.toml ./gitleaks.toml
cp github-privacy-push-guard/examples/privacy-guard-allowlist ./.privacy-guard-allowlist

pre-commit install
pre-commit run --all-files

cp github-privacy-push-guard/examples/pre-push .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

または、このパッケージを展開したディレクトリから:

```bash
./install.sh /path/to/your/repo
```

## 手動検査

```bash
python3 tools/privacy_guard.py --staged --fail-on medium
python3 tools/privacy_guard.py --all-files --fail-on medium
gitleaks detect --source . --redact
trufflehog filesystem . --only-verified
```

## 注意

- 検出されたsecretは出力上でマスクされます。
- すでにGitHubへpushしたsecretは漏洩済みとして扱い、必ず revoke / rotate してください。
- `git rm` だけではGit履歴から消えません。
