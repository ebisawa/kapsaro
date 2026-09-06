---
name: kapsaro-writing
description: kapsaro の README、ガイド、CLI ヘルプ、コミット・PR の文章を執筆・推敲するときに使う。意味と要件を保つ表現、根拠に基づく技術訂正、日英の情報対応、章の再構成とリンク保全を扱う。
---

# kapsaro の文書執筆・推敲

読者が用途を判断し、手順を実行し、保証の範囲を理解できる文章にする。文書の所在とリポジトリの規約は CLAUDE.md を参照する。

## 意味と要件を保つ

- 編集開始時の本文を基準にする。未コミット変更を含めて読み、既存の編集を保持する。
- 表現の変更では、主語、対象、条件、時点、保証範囲、義務・推奨・許可の強さを保つ。必要条件を推奨へ弱めたり、推奨を必須にしたりしない。
- 技術説明に誤りがあれば、現行の仕様、実装、一次資料に照合して訂正する。根拠と変更理由を作業報告に記録し、単なる言い換えと区別する。公開文書へ非公開資料の所在を書かない。
- コマンド、設定名、値、数値、数式、JSON、行形式、図は本文と別に照合する。実質的な変更には根拠が要る。
- 重複説明は統合できる。ただし、固有の前提条件、制約、例、失敗時の手順を移動先に残す。

## 文書ごとの目的

| 文書 | 読者が知ること | 書き方 |
| --- | --- | --- |
| 製品概要 | 用途への適合、限界、導入の流れ | 具体的な用途と判断材料を簡潔に示す。宣伝調の断定を避ける |
| ユーザーガイド・WSL 補足 | 準備、操作、確認、復旧 | 前提条件をコマンドより先に置き、結果と次の手順を示す |
| セキュリティ設計 | 保証の根拠、前提、残余リスク | 検証対象と保証の範囲を説明する。権威を感じさせる語彙で厳密さを代用しない |
| README | 概要、導入方法、詳細の参照先 | 最初に用途を伝え、詳しい運用はガイドへつなぐ |
| CLI ヘルプ | 引数の用途、既定値、制約 | 実装に沿う短い説明にする |
| コミット・PR | 問題、変更後の挙動、検証結果 | 英語で書き、レビューに必要な事実を示す |

## 英語の表現

主語と動作を明確にし、短く普通の語を選ぶ。能動態を基本としつつ、処理対象を主題にするほうが自然なら受動態を使う。修飾語や抽象名詞を増やすだけの言い換えは避ける。

| 元の表現 | 改訂例 | 保つ意味 |
| --- | --- | --- |
| It is designed to provide support for encrypted file sharing. | It shares encrypted files. | 実際に備える機能 |
| No dedicated server is required. | No dedicated server is required. | 既に明快なら変更不要 |
| You must verify the signature before accepting the file. | Verify the signature before accepting the file. | 受け入れ前の必須確認 |
| It is recommended that you review the changes. | We recommend reviewing the changes. | 推奨の強さ |

英語の見出しは既存の Title Case に揃える。先頭・末尾と主要語を大文字にし、途中の冠詞、接続詞、短い前置詞は小文字にする。SSH、HPKE、Kapsaro などの表記と識別子の綴りを保つ。単に格調を上げるために動詞を名詞へ変えない。

並列の箇条書きは構文を揃える。コマンド内のコメントは直後の操作の目的を短く示し、ソースコードのコメントは英語で書く。

## 日本語の表現

本文は「です・ます調」に統一する。表や短い箇条書きには名詞句を使ってよい。手順は誰が何をするかが分かる文にする。

| 元の表現 | 改訂例 | 注意点 |
| --- | --- | --- |
| 〜することができます | 〜できます | 機能の説明を実行指示へ変えない |
| 〜する必要があります | 〜が必要です／〜してください | 必須条件のまま伝える |
| 〜することが推奨されます | 〜を推奨します | 必須へ変えない |
| 〜によって提供される | 〜が提供する | 主語が明確になる場合に使う |

慣例がある専門語と識別子を除き、日本語の用語を選ぶ。「秘密情報」を一律に「シークレット」へ、「鍵更新」を一律に「ローテーション」へ置き換えない。専門語は初出で役割を説明する。例えば signature.mac は内容鍵の所持を確認する MAC、signer_pub は署名に含まれる検証用公開鍵の情報、known_keys は承認済み鍵の記録、recipient_sets は承認済み受信者集合の記録として導入する。

長い連体修飾や「の」の連続は文を分けて解消する。「境界」「中心」「効く」などの抽象的な表現より、検証する対象や操作の結果を書く。

## セキュリティ説明と運用手順

- 署名の有効性、内容鍵の所持、メンバーとしての認可、利用者の承認、本人確認を区別する。一つの検証に別の保証を持たせない。
- 暗号の安全性は前提と範囲を添えて説明する。「衝突しない」「確率はゼロ」「完全に安全」といった断定は、実際の保証に照らして見直す。
- メンバー鍵の更新、受信者の変更、内容鍵の更新、外部サービスの資格情報の失効を区別する。漏洩前の暗号文や既に取得された平文への影響も説明する。
- 確認用の例は秘密値をログや履歴へ出さない。実読の確認には kapsaro run -- true、入力には --stdin や非表示入力などを使う。値を表示するコマンドを説明する場合は、その動作が分かるようにする。
- メンバー・鍵・CI の変更手順には、対象ファイルの確認、署名検証、実読、変更の共有、利用側の確認までの完了条件を示す。実施していない CI や動作確認を検証済みと書かない。

## 構成変更とリンクの保全

長文の再構成では、編集前に旧節と移動先の対応を整理する。まず読む順序を決め、固有情報を移してから重複を統合する。JSON、行形式、数式、図などの具体例は、その説明と一緒に移す。

既存の明示アンカーは対応する本文と一緒に移す。見出しの改題や番号変更で自動生成アンカーが変わる場合は、旧アンカーを明示的な id としてその本文に残す。旧リンクが無関係な場所を指すだけでは保全にならない。同一文書内の id の重複を避ける。

目次、節番号、本文中の節参照、README と他言語版からのリンクを更新する。目次の表示名は移動後の見出しに揃える。旧リンクの互換性と新リンクの到達先を両方確認する。

## 表記と日英の対応

太字やコード表記を装飾のために付けない。識別子を本文と区別する表記と強調を区別し、リポジトリの指示に従う。コードブロックは実行例やデータ形式に使う。アラートは実際に前提条件や危険を見落としやすい箇所に限る。行末と空行に空白を残さない。

日英は情報、条件、手順、保証の範囲を対応させる。段落数、コメント行数、表の行数を完全一致させる必要はない。読者が同じ判断と操作に到達できることを確認する。

1. 各文書を全文読み、対象読者に必要な情報と操作の順序を確認する。
2. 日英を節ごとに照合し、片方だけにある条件、説明、失敗時の処置を確認する。
3. コマンドとデータ例を比較する。コメントや文章の自然な差と、引数・値・フィールドの実質的な差を分ける。
4. 構造変更があれば、旧節との対応表で情報とリンクの保持を確認する。
5. 規約検査とリンク検査を実行し、技術訂正の根拠と未検証事項を報告する。対応する変更履歴があれば更新する。

## 構造検査の例

以下はリポジトリのルートで実行する。見出し、明示アンカー、コードブロックの一覧を取り出す補助検査であり、翻訳品質やリンク先の存在を保証するものではない。件数の差は調査の手掛かりとし、意味の対応は全文レビューで確認する。

```bash
./scripts/check-repo-conventions.sh
git diff --check

python3 - <<'PY'
import re
from collections import Counter
from pathlib import Path


def structure(text):
    headings, anchors, blocks = [], [], []
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence:
            if (marker and marker[1][0] == fence[0]
                    and len(marker[1]) >= fence[1]
                    and not marker[2].strip()):
                fence = None
            continue
        if marker:
            fence = (marker[1][0], len(marker[1]))
            blocks.append((number, marker[2].strip()))
            continue
        heading = re.match(r"^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if heading:
            headings.append((number, len(heading[1]), heading[2]))
        anchors.extend(re.findall(r'<a\s+(?:id|name)="([^"]+)"', line))
    if fence:
        raise ValueError("Unclosed code fence")
    duplicates = [key for key, count in Counter(anchors).items() if count > 1]
    if duplicates:
        raise ValueError(f"Duplicate explicit anchors: {duplicates}")
    return headings, anchors, blocks


for stem in ("product_brief", "user_guide", "security_design", "wsl_user_guide"):
    for language in ("en", "ja"):
        path = Path(f"guides/{stem}_{language}.md")
        headings, anchors, blocks = structure(path.read_text())
        print(f"{path}: {len(headings)} headings, {len(anchors)} anchors, "
              f"{len(blocks)} code blocks")
        for number, level, title in headings:
            print(f"  {number}: {'#' * level} {title}")
print("Structure inventory complete; review meaning and links separately.")
PY
```

この例はガイドで使う ATX 見出しと、最大3スペースで字下げされたバッククォート・チルダのフェンスに対応する。引用・リスト内のフェンス、Setext 見出しなど別の構文を導入した場合は Markdown パーサーを使う。自動生成アンカーの互換性や文書間リンクは、レンダラーの規則に合わせて別途検査する。

