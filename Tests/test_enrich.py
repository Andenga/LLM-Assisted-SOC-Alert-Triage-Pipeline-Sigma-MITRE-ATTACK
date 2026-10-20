from triageforge.enrich import technique_ids_from_tags

def test_tag_parsing():
    tags = ["attack.execution", "attack.t1059.001", "attack.t1059"]
    assert technique_ids_from_tags(tags) == ["T1059.001", "T1059"]