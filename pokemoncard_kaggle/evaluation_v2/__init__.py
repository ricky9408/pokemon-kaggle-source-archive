"""Cohort-aware candidate qualification for the Pokemon TCG competition.

The package deliberately stays small.  It owns immutable evaluation inputs and
structured verdicts; historical research scripts remain outside the trusted
qualification path.
"""

from .schemas import CandidateIdentity, CohortManifest, EpisodeRecord

__all__ = ["CandidateIdentity", "CohortManifest", "EpisodeRecord"]
