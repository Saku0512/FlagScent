# FlagScent

CTFリバースエンジニアリング支援ツール - フラグ候補の自動発見

## 概要

FlagScentは、Linux ELFバイナリを自動解析し、CTFリバース問題でよく見られる**フラグ候補**を自動抽出するPoC（概念実証）ツールです。

完全自動化を目指すのではなく、静的解析、動的トレース、ヒューリスティックスコアリングを組み合わせることで、信頼性の高いフラグ候補を明確な説明とともに提示することを目的としています。

**設計哲学**: "Smell the flag, don't brute-force it."

## 機能

- **静的解析**: radare2を使用した文字列抽出と関数解析
- **動的解析**: ltrace/straceを使用した実行時トレース
- **シンボリック実行**: angrを使用したパス探索（オプション）
- **ヒューリスティック分析**: フラグ候補の検証とスコアリング
- **ランキング**: スコアに基づく候補の自動ランキング
- **バイナリ構造解析**: radare2を使用した関数リスト、逆アセンブリ、構造分析

## インストール

### 前提条件

- Linux (x86_64)
- Python 3.11+
- 外部ツール:
  - radare2
  - ltrace
  - strace

### インストール方法

```bash
# リポジトリをクローン
git clone <repository-url>
cd FlagScent

# pipでインストール（開発モード）
pip install -e .

# または通常のインストール
pip install .
```

## 使用方法

### フラグ候補の検索

```bash
# 基本的な使用方法
flagscent binary

# JSON形式で出力
flagscent binary --json output.json

# シンボリック実行を無効化
flagscent binary --no-symbolic

# 表示する候補数を指定
flagscent binary --limit 20
```

### バイナリ構造の分析

```bash
# バイナリ構造を分析（関数リスト、エントリーポイント、インポートなど）
flagscent binary --analyze

# 特定の関数を逆アセンブル
flagscent binary --disassemble main

# 複数のオプションを組み合わせ
flagscent binary --analyze --limit 5
```

## 出力例

### フラグ候補の検索結果

```
============================================================
Flag Candidates (ranked by score)
============================================================

[1] score=92.0  CTF{rev_is_fun}
    source: ltrace strcmp
    method: dynamic

[2] score=85.5  flag{example_flag}
    source: static string extraction (r2)
    method: static
...
```

### バイナリ構造分析結果（--analyze）

```
============================================================
Binary Analysis Summary
============================================================

Entry Point: 0x1040

Functions: 15

Key Functions:
  main                            @ 0x1149 (size: 234)
  check_flag                      @ 0x11e0 (size: 89)
  ...

Main Function:
  Name: main
  Address: 0x1149
  Size: 234 bytes

Imported Functions: 8

Interesting Imports:
  - strcmp
  - puts
  - printf
  - fgets

============================================================

Disassembly of 'main':
============================================================
            ;-- main:
            ; DATA XREF from entry0 @ 0x1030
┌ 234: int main (int argc, char **argv, char **envp);
│ ...
└
```

## プロジェクト構造

```
FlagScent/
├── flagscent/
│   ├── __init__.py
│   ├── cli.py              # CLIエントリーポイント
│   ├── analyzer.py          # メインアナライザー
│   ├── static_analyzer.py   # 静的解析（radare2）
│   ├── dynamic_analyzer.py  # 動的解析（ltrace/strace）
│   ├── symbolic_analyzer.py # シンボリック実行（angr）
│   ├── r2_analyzer.py       # radare2構造解析ユーティリティ
│   ├── heuristic.py         # ヒューリスティック分析
│   ├── scorer.py            # スコアリング
│   └── models.py            # データモデル
├── tests/                   # テストスイート
├── pyproject.toml
├── requirements.txt
└── README.md
```

## テスト

テストスイートは `tests/` ディレクトリにあります。

```bash
# 仮想環境を作成（推奨）
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# または
venv\Scripts\activate  # Windows

# 依存関係をインストール
pip install -e ".[dev]"

# すべてのテストを実行
pytest tests/ -v

# カバレッジレポート付きで実行
pytest tests/ --cov=flagscent --cov-report=html

# 特定のテストファイルを実行
pytest tests/test_heuristic.py -v
```

### テストカバレッジ

- `test_models.py`: データモデルのテスト
- `test_heuristic.py`: ヒューリスティック分析のテスト
- `test_scorer.py`: スコアリングとランキングのテスト
- `test_static_analyzer.py`: 静的解析のテスト
- `test_dynamic_analyzer.py`: 動的解析のテスト
- `test_analyzer.py`: メインアナライザーの統合テスト

## コマンドラインオプション

### フラグ候補検索オプション

- `binary`: 解析するELFバイナリのパス（必須）
- `--json FILE`: 結果をJSON形式で出力（`-`を指定するとstdoutに出力）
- `--no-symbolic`: シンボリック実行を無効化
- `--symbolic-timeout SECONDS`: シンボリック実行のタイムアウト（デフォルト: 30秒）
- `--limit N`: 表示する候補数の上限（デフォルト: 10）

### バイナリ構造解析オプション

- `--analyze`: バイナリ構造を分析（関数リスト、エントリーポイント、インポート、main関数の逆アセンブリ）
- `--disassemble FUNCTION`: 指定した関数の逆アセンブリを表示

### その他

- `--version`: バージョン情報を表示
- `-h, --help`: ヘルプメッセージを表示

## 開発状況

現在、PoC（概念実証）段階です。詳細は `requirementsDefinition.md` を参照してください。

## ライセンス

LICENSEファイルを参照してください。