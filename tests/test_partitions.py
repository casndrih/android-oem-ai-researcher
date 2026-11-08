from oem_research.partitions import inspect_partitions

def test_partition_name_candidate(tmp_path):
    (tmp_path/"vendor_boot.img").write_bytes(b"ANDROID!")
    rows=inspect_partitions(tmp_path)
    assert "vendor_boot" in rows[0]["partition_candidates"]
