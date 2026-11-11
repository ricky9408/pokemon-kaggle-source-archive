import pytest

from evaluation_v2.value_head import PublicValueHead


def test_value_head_scores_embedding_signal() -> None:
    model = PublicValueHead(
        buckets=2,
        dimension=1,
        hidden=1,
        embeddings=(0.0, 2.0),
        value_w1=(1.0,),
        value_b1=(0.0,),
        value_w2=(1.0,),
        value_b2=0.0,
    )
    assert model.score_buckets(((1,),)) > model.score_buckets(((0,),))


def test_value_head_rejects_bad_bucket() -> None:
    model = PublicValueHead(1, 1, 1, (0.0,), (1.0,), (0.0,), (1.0,), 0.0)
    with pytest.raises(ValueError, match="range"):
        model.score_buckets(((2,),))
