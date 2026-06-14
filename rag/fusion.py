"""
rag/fusion.py - Reciprocal Rank Fusion (RRF) để fuse kết quả từ nhiều retrievers.

Công thức: score(d) = sum_i 1/(k + rank_i(d))
"""

from typing import List, Tuple, Dict


def rrf_fuse(
    rankings: List[List[str]],
    k: int = 60
) -> List[Tuple[str, float]]:
    """Reciprocal Rank Fusion.

    Args:
        rankings: List các ranked lists. Mỗi list là list of doc_ids sắp xếp giảm.
                 Ví dụ: [["doc1", "doc2", ...], ["doc3", "doc1", ...], ...]
        k: RRF parameter (thường 60)

    Returns:
        List[(doc_id, fused_score)] sắp xếp giảm theo score
    """
    if not rankings:
        return []

    # Build rank mapping
    fused_scores = {}

    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            score = 1.0 / (k + rank)
            if doc_id not in fused_scores:
                fused_scores[doc_id] = 0.0
            fused_scores[doc_id] += score

    # Sort by score
    result = sorted(fused_scores.items(), key=lambda x: x[1], reverse=True)
    return result


def normalize_rankings(
    score_dicts: List[Dict[str, float]],
    top_k: int = 20
) -> List[List[str]]:
    """Normalize score dictionaries to ranked lists for RRF.

    Args:
        score_dicts: List[Dict[doc_id -> score]]
        top_k: Lấy top-k từ mỗi retriever

    Returns:
        List[List[str]] rankings cho RRF
    """
    rankings = []

    for score_dict in score_dicts:
        # Sort by score, get top-k
        ranked = sorted(score_dict.items(), key=lambda x: x[1], reverse=True)
        ranked_ids = [doc_id for doc_id, _ in ranked[:top_k]]
        rankings.append(ranked_ids)

    return rankings


def fuse_with_scores(
    retriever_results: List[Dict[str, float]],
    k: int = 60
) -> List[Tuple[str, float]]:
    """Convenience function: fuse từ list of score dicts.

    Args:
        retriever_results: List[Dict[doc_id -> score]]
        k: RRF parameter

    Returns:
        Fused results
    """
    rankings = normalize_rankings(retriever_results)
    return rrf_fuse(rankings, k=k)
