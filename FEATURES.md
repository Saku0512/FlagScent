# FlagScent - 機能一覧

## 概要

FlagScent v0.1.0 - CTFリバースエンジニアリング支援ツール

**設計哲学**: "Smell the flag, don't brute-force it."

---

## 実装済み機能

### 1. 静的解析 (Static Analysis)

#### 1.1 文字列抽出
- **実装状況**: ✅ 実装済み
- **技術**: radare2 (r2pipe) / stringsコマンド（フォールバック）
- **機能**:
  - データセクションからの文字列抽出 (`iz`)
  - 全セクションからの文字列抽出 (`izz`)
  - ノイズフィルタリング（関数名、ライブラリパスなどを除外）
  - フラグ候補らしい文字列の優先抽出
- **モジュール**: `flagscent/static_analyzer.py`

#### 1.2 関数解析
- **実装状況**: ✅ 実装済み
- **技術**: radare2 (r2pipe)
- **機能**:
  - 関数リスト取得 (`afl` / `aflj`)
  - 関数の逆アセンブリ (`pdf @ function`)
  - エントリーポイント取得
  - main関数の検出
- **モジュール**: `flagscent/static_analyzer.py`, `flagscent/r2_analyzer.py`

#### 1.3 インポート関数の識別
- **実装状況**: ✅ 実装済み
- **技術**: radare2 (r2pipe)
- **機能**:
  - インポートされたlibc関数の検出 (`ii`)
  - strcmp, memcmp, puts, printfなどの検出
- **モジュール**: `flagscent/static_analyzer.py`

#### 1.4 文字列参照の検索
- **実装状況**: ✅ 実装済み（基本実装）
- **技術**: radare2 (r2pipe)
- **機能**:
  - 特定文字列への参照検索 (`axt`)
- **モジュール**: `flagscent/static_analyzer.py`

---

### 2. 動的解析 (Dynamic Analysis)

#### 2.1 ltrace解析
- **実装状況**: ✅ 実装済み
- **技術**: ltrace
- **機能**:
  - strcmp/strncmp/memcmp呼び出しの監視
  - puts/printf/fputs/fprintf呼び出しの監視
  - 関数引数の抽出（両方の引数を候補として抽出）
  - エスケープされた引用符と省略記号（`...`）への対応
  - 重複排除
- **モジュール**: `flagscent/dynamic_analyzer.py`

#### 2.2 strace解析
- **実装状況**: ✅ 実装済み
- **技術**: strace
- **機能**:
  - read/write syscallの監視
  - 文字列データの抽出
  - 16進数エンコードデータのデコード
- **モジュール**: `flagscent/dynamic_analyzer.py`

---

### 3. シンボリック実行 (Symbolic Execution)

#### 3.1 angrによるパス探索
- **実装状況**: ⚠️ 骨格のみ（未完成）
- **技術**: angr
- **機能**:
  - 成功パスへの探索（プレースホルダー）
  - タイムアウト制御
- **モジュール**: `flagscent/symbolic_analyzer.py`
- **備考**: 実装は開始されているが、完全な機能は未実装

---

### 4. ヒューリスティック分析 (Heuristic Analysis)

#### 4.1 フラグ検証
- **実装状況**: ✅ 実装済み
- **機能**:
  - フラグプレフィックス検出（CTF{, flag{, Alpaca{など）
  - 印刷可能文字比率の計算
  - エントロピー推定（Shannon entropy）
  - 括弧バランス検証
  - 長さ検証（15-80文字）
- **モジュール**: `flagscent/heuristic.py`

#### 4.2 スコアリング
- **実装状況**: ✅ 実装済み
- **機能**:
  - ヒューリスティックスコア計算（0-100点）
  - ソース信頼度ボーナス（動的 > シンボリック > 静的）
  - 総合スコア計算
- **モジュール**: `flagscent/scorer.py`

#### 4.3 ランキング
- **実装状況**: ✅ 実装済み
- **機能**:
  - スコアによる降順ソート
  - 重複候補の排除
- **モジュール**: `flagscent/scorer.py`

---

### 5. バイナリ構造解析 (Binary Structure Analysis)

#### 5.1 構造分析
- **実装状況**: ✅ 実装済み
- **技術**: radare2 (r2pipe)
- **機能**:
  - 関数リスト表示
  - エントリーポイント表示
  - インポート関数表示
  - main関数の情報表示
  - main関数の自動逆アセンブリ
- **モジュール**: `flagscent/r2_analyzer.py`

#### 5.2 関数逆アセンブリ
- **実装状況**: ✅ 実装済み
- **技術**: radare2 (r2pipe)
- **機能**:
  - 指定関数の逆アセンブリ表示
- **モジュール**: `flagscent/static_analyzer.py`, `flagscent/r2_analyzer.py`

---

### 6. CLI機能

#### 6.1 フラグ候補検索
- **実装状況**: ✅ 実装済み
- **コマンド**: `flagscent binary`
- **オプション**:
  - `--json FILE`: JSON形式で出力
  - `--no-symbolic`: シンボリック実行を無効化
  - `--symbolic-timeout SECONDS`: タイムアウト設定
  - `--limit N`: 表示候補数の上限
- **モジュール**: `flagscent/cli.py`

#### 6.2 バイナリ構造解析
- **実装状況**: ✅ 実装済み
- **コマンド**: `flagscent binary --analyze`
- **コマンド**: `flagscent binary --disassemble FUNCTION`
- **モジュール**: `flagscent/cli.py`

#### 6.3 その他
- **実装状況**: ✅ 実装済み
- **機能**:
  - `--version`: バージョン表示
  - `-h, --help`: ヘルプ表示
- **モジュール**: `flagscent/cli.py`

---

### 7. データモデル

#### 7.1 FlagCandidate
- **実装状況**: ✅ 実装済み
- **機能**:
  - 候補文字列、スコア、抽出方法、ソース情報の管理
  - JSON形式への変換
  - 文字列表現
- **モジュール**: `flagscent/models.py`

#### 7.2 AnalysisMethod
- **実装状況**: ✅ 実装済み
- **機能**:
  - 解析方法の列挙型（STATIC, DYNAMIC, SYMBOLIC）
- **モジュール**: `flagscent/models.py`

---

### 8. テスト

#### 8.1 テストスイート
- **実装状況**: ✅ 実装済み
- **カバレッジ**:
  - `test_models.py`: データモデル
  - `test_heuristic.py`: ヒューリスティック分析（66テスト）
  - `test_scorer.py`: スコアリング
  - `test_static_analyzer.py`: 静的解析
  - `test_dynamic_analyzer.py`: 動的解析
  - `test_analyzer.py`: メインアナライザー
- **モジュール**: `tests/`

---

## 未実装 / 部分実装機能

### 1. シンボリック実行
- **状況**: ⚠️ 骨格のみ
- **必要な実装**:
  - 成功パスへの探索ロジック
  - 制約生成
  - 候補文字列の生成

### 2. 文字列参照の詳細解析
- **状況**: ⚠️ 基本実装のみ
- **改善の余地**:
  - 参照先の関数名取得
  - 参照コンテキストの詳細化

---

## 依存関係

### Pythonパッケージ
- `r2pipe>=1.7.0`: radare2との連携
- `angr>=9.2.0`: シンボリック実行（未使用）

### 外部ツール
- `radare2`: 静的解析
- `ltrace`: 動的解析（ライブラリ呼び出し）
- `strace`: 動的解析（システムコール）
- `strings`: 文字列抽出（フォールバック）

---

## プロジェクト構造

```
FlagScent/
├── flagscent/
│   ├── __init__.py              # パッケージ初期化
│   ├── cli.py                   # CLIエントリーポイント
│   ├── analyzer.py              # メインアナライザー（統合）
│   ├── static_analyzer.py       # 静的解析
│   ├── dynamic_analyzer.py      # 動的解析
│   ├── symbolic_analyzer.py     # シンボリック実行（未完成）
│   ├── r2_analyzer.py           # radare2構造解析ユーティリティ
│   ├── heuristic.py             # ヒューリスティック分析
│   ├── scorer.py                # スコアリングとランキング
│   └── models.py                # データモデル
├── tests/                        # テストスイート
├── pyproject.toml               # パッケージ設定
├── requirements.txt             # 依存関係
├── README.md                    # メインドキュメント
└── FEATURES.md                  # このファイル
```

---

## 使用例

### フラグ候補の検索
```bash
flagscent binary
flagscent binary --json output.json
flagscent binary --no-symbolic --limit 20
```

### バイナリ構造の分析
```bash
flagscent binary --analyze
flagscent binary --disassemble main
```

---

## バージョン情報

- **バージョン**: 0.1.0
- **作者**: Saku0512
- **ステータス**: PoC（概念実証）段階

