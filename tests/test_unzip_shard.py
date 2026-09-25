"""2026-09-25:GitHub 拒绝推送 —— data/all_vuln 单目录 1,054,541 个文件,树对象 52,848,877 字节超过非 blob 对象上限,
「每日OSV数据同步」自 09-22 起每次失败,下游 OSV 数据停在 09-18。修法:按 id 前缀分片 data/all_vuln/<PREFIX>/<ID>.json
(CVE 24 万文件的树 ≈10 MB);顶层残留的平铺文件在首次分片轮清掉;下游 data-infra 递归遍历、按文件名取 id,无需改动。"""
import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from osv_sync.utils import shard_of, unzip_osv_data  # noqa: E402


def _zip(tmp_path, names):
    p = tmp_path / "all.zip"
    with zipfile.ZipFile(p, "w") as z:
        for n in names:
            z.writestr(n, '{"id": "%s"}' % n[:-5])
    return p


def test_shard_of_uses_id_prefix():
    assert shard_of("CVE-2026-1234.json") == "CVE"
    assert shard_of("GHSA-xxxx-yyyy-zzzz.json") == "GHSA"
    assert shard_of("PYSEC-2021-1.json") == "PYSEC"
    assert shard_of("weird.json") == "OTHER"


def test_unzip_writes_sharded_paths_skips_prefixes_and_removes_flat_leftovers(tmp_path):
    data = tmp_path / "data"; all_dir = data / "all_vuln"; all_dir.mkdir(parents=True)
    (all_dir / "CVE-2020-1.json").write_text("old flat")            # 旧布局残留,应被清掉
    (all_dir / "notes.txt").write_text("keep")                       # 非 json 不动
    z = _zip(tmp_path, ["CVE-2026-1.json", "GHSA-aaaa-bbbb-cccc.json", "CGA-1.json", "MAL-2026-1.json"])
    stats = unzip_osv_data(z, data, exclude_prefixes=["CGA-"])
    assert stats == {"extracted": 3, "skipped": 1, "flat_removed": 1}
    assert (all_dir / "CVE" / "CVE-2026-1.json").is_file()
    assert (all_dir / "GHSA" / "GHSA-aaaa-bbbb-cccc.json").is_file()
    assert (all_dir / "MAL" / "MAL-2026-1.json").is_file()
    assert not (all_dir / "CGA" / "CGA-1.json").exists() and not (all_dir / "CGA-1.json").exists()
    assert not (all_dir / "CVE-2020-1.json").exists(), "顶层平铺 json 必须清掉(迁移一次)"
    assert (all_dir / "notes.txt").exists()
    assert sorted(p.name for p in all_dir.iterdir()) == ["CVE", "GHSA", "MAL", "notes.txt"]


def test_workflow_guard_can_be_lifted_for_the_migration_commit_only():
    wf = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "daily-sync.yml").read_text(encoding="utf-8")
    assert "allow_bulk" in wf and "workflow_dispatch" in wf
    assert 'if [ "$pending" -gt 100000 ] && [ "${ALLOW_BULK:-false}" != "true" ]' in wf
