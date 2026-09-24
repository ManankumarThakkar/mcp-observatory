from analyzer.sampling import draw


def test_the_draw_is_reproducible_for_a_seed() -> None:
    items = [f"item-{n:03d}" for n in range(100)]

    assert draw(items, 10, seed=7, key=lambda s: (s,)) == draw(items, 10, seed=7, key=lambda s: (s,))


def test_the_draw_does_not_depend_on_input_order() -> None:
    """The whole reason this is a hash and not a seeded shuffle."""
    items = [f"item-{n:03d}" for n in range(100)]

    assert draw(items, 10, seed=7, key=lambda s: (s,)) == draw(
        list(reversed(items)), 10, seed=7, key=lambda s: (s,)
    )


def test_adding_items_does_not_reorder_the_ones_already_there() -> None:
    """The property that protects hand-made labels. Each item's position
    depends only on its own identity and the seed, so a later scan finding new
    things cannot reshuffle a sample somebody has already spent hours
    labelling. A seeded shuffle does not have this property.
    """
    first = [f"item-{n:03d}" for n in range(50)]
    grown = first + [f"later-{n:03d}" for n in range(50)]

    order_before = draw(first, 50, seed=7, key=lambda s: (s,))
    order_after = [s for s in draw(grown, 100, seed=7, key=lambda s: (s,)) if s in set(first)]

    assert order_before == order_after


def test_a_size_beyond_the_population_returns_the_population() -> None:
    assert len(draw(["a", "b"], 10, seed=7, key=lambda s: (s,))) == 2


def test_ties_on_the_hashed_part_are_broken_by_the_rest_of_the_key() -> None:
    """Two items sharing a hashed identity would otherwise be ordered by
    whichever arrived first, reintroducing the input-order dependence."""
    pairs = [("dup", "b"), ("dup", "a"), ("other", "c")]

    forward = draw(pairs, 3, seed=7, key=lambda p: (p[0], p[1]))
    backward = draw(list(reversed(pairs)), 3, seed=7, key=lambda p: (p[0], p[1]))

    assert forward == backward
