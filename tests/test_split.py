from __future__ import annotations

from collections import Counter

import pytest
from helpers import case_block, make_dataset, many_cases

from wpbench.cases import load_cases
from wpbench.split import SplitError, apply_to_text, assign, check_splits_file, write_splits_file
from wpbench.vocab import CLASSES


@pytest.fixture
def dataset(tmp_path):
    return make_dataset(tmp_path)


def cases_of(dataset, n=40, classes=None):
    return load_cases(dataset(*many_cases(n, classes)))[0]


def test_assignment_has_the_requested_sizes_and_is_stratified(dataset):
    cases = cases_of(dataset, 40)
    r = assign(cases, "s1", 15, 25)
    assert (r.dev, r.test) == (15, 25) and set(r.assignment.values()) == {"dev", "test"}
    by_class = Counter(c.cls for c in cases)
    dev_by_class = Counter(c.cls for c in cases if r.assignment[c.id] == "dev")
    for cls, n in by_class.items():
        assert abs(dev_by_class[cls] - n * 15 / 40) < 1  # within one case of the proportional share


def test_same_seed_same_result_and_a_different_seed_differs(dataset):
    cases = cases_of(dataset, 40)
    a, b, c = assign(cases, "s1"), assign(cases, "s1"), assign(cases, "s2")
    assert a.assignment == b.assignment and a.assignment != c.assignment


def test_result_does_not_depend_on_input_order(dataset):
    cases = cases_of(dataset, 30)
    assert assign(cases, "x").assignment == assign(list(reversed(cases)), "x").assignment


def test_small_and_single_class_datasets(dataset):
    cases = cases_of(dataset, 6, classes=("sqli",))
    r = assign(cases, "s", 15, 25)
    assert r.dev + r.test == 6 and r.dev >= 1 and r.test >= 1
    one = load_cases(dataset(case_block(1)))[0]
    assert assign(one, "s").dev == 1


def test_refuses_to_reassign_without_force_and_on_empty(dataset):
    cases = load_cases(dataset(case_block(1, split="test"), case_block(2)))[0]
    with pytest.raises(SplitError, match="frozen"):
        assign(cases, "s")
    assert assign(cases, "s", force=True)
    with pytest.raises(SplitError, match="no cases"):
        assign([], "s")
    with pytest.raises(SplitError, match="positive"):
        assign(cases_of(dataset, 4), "s", 0, 1)


def test_apply_to_text_sets_and_replaces_split_and_keeps_everything_else():
    text = (
        "# header comment\n\n[[case]]\nid = \"wp-0001\"\nslug = \"a\"\n\n[case.truth]\nfile = \"x.php\"\n\n"
        "[[case]]\nid = \"wp-0002\"\nsplit = \"dev\"\nslug = \"b\"\n\n[[case]]\nid = \"wp-0003\"\nslug = \"c\""
    )
    out = apply_to_text(text, {"wp-0001": "test", "wp-0002": "test", "wp-0003": "dev"})
    assert out.startswith("# header comment")
    assert 'id = "wp-0001"\nslug = "a"\nsplit = "test"\n\n[case.truth]\nfile = "x.php"' in out
    assert 'id = "wp-0002"\nsplit = "test"\nslug = "b"' in out and out.count("split =") == 3
    assert out.rstrip().endswith('slug = "c"\nsplit = "dev"')


def test_apply_to_text_round_trips_through_the_validator(dataset, tmp_path):
    path = dataset(*many_cases(12))
    cases = load_cases(path)[0]
    result = assign(cases, "round-trip", 15, 25)
    path.write_text(apply_to_text(path.read_text(), result.assignment))
    reloaded, issues = load_cases(path)
    assert [i for i in issues if i.level == "error"] == []
    assert {c.id: c.split for c in reloaded} == result.assignment


def test_splits_file_is_written_and_cross_checked(dataset):
    path = dataset(*many_cases(8))
    cases = load_cases(path)[0]
    result = assign(cases, "audit-me")
    splits = path.with_name("splits.toml")
    write_splits_file(splits, result)
    text = splits.read_text()
    assert 'seed = "audit-me"' in text and "dev = [" in text and "test = [" in text
    assert check_splits_file(splits, cases) == [] or all(i.field == "split" for i in check_splits_file(splits, cases))
    path.write_text(apply_to_text(path.read_text(), result.assignment))
    synced = load_cases(path)[0]
    assert check_splits_file(splits, synced) == []
    synced[0].split = "test" if synced[0].split == "dev" else "dev"
    assert any("splits.toml says" in str(i) for i in check_splits_file(splits, synced))
    assert check_splits_file(path.with_name("absent.toml"), synced) == []


def test_all_known_classes_can_be_stratified(dataset):
    cases = load_cases(dataset(*[case_block(i + 1, **{"class": c}) for i, c in enumerate(CLASSES)]))[0]
    r = assign(cases, "all-classes")
    assert r.dev + r.test == len(CLASSES)


def test_pinned_cases_go_to_dev_and_the_sizes_still_hold(dataset):
    cases = cases_of(dataset, 40)
    pins = [c.id for c in cases[:6]]
    r = assign(cases, "s1", 15, 25, pin_dev=pins)
    assert (r.dev, r.test) == (15, 25) and all(r.assignment[i] == "dev" for i in pins) and r.pinned == tuple(sorted(pins))
    dev_by_class = Counter(c.cls for c in cases if r.assignment[c.id] == "dev")
    for cls, n in Counter(c.cls for c in cases).items():
        assert abs(dev_by_class[cls] - n * 15 / 40) <= 1.5  # pins may tilt a class, never by much


def test_pins_are_deterministic_independent_of_order_and_validated(dataset):
    cases = cases_of(dataset, 30)
    pins = [cases[0].id, cases[7].id]
    a = assign(cases, "x", pin_dev=pins)
    assert a.assignment == assign(list(reversed(cases)), "x", pin_dev=reversed(pins)).assignment
    assert a.assignment != assign(cases, "y", pin_dev=pins).assignment
    with pytest.raises(SplitError, match="unknown"):
        assign(cases, "x", pin_dev=["wp-9999"])
    with pytest.raises(SplitError, match="do not fit"):
        assign(cases, "x", 1, 29, pin_dev=[c.id for c in cases[:5]])


def test_without_pins_the_result_is_unchanged(dataset):
    cases = cases_of(dataset, 40)
    assert assign(cases, "s1").assignment == assign(cases, "s1", pin_dev=()).assignment


def test_splits_file_records_the_pins(dataset, tmp_path):
    cases = cases_of(dataset, 20)
    r = assign(cases, "s", pin_dev=[cases[0].id])
    out = tmp_path / "splits.toml"
    write_splits_file(out, r)
    assert f'pinned_dev = ["{cases[0].id}"]' in out.read_text()
    import tomllib

    assert tomllib.loads(out.read_text())["pinned_dev"] == [cases[0].id]
