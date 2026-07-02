"""Token estimation and cost confirmation before any LLM calls."""

from dataclasses import dataclass

# Pricing per 1M tokens as of mid-2025
HAIKU_IN = 0.80 / 1_000_000
HAIKU_OUT = 4.00 / 1_000_000
SONNET_IN = 3.00 / 1_000_000
SONNET_OUT = 15.00 / 1_000_000


@dataclass
class CostEstimate:
    haiku_input_tokens: int
    haiku_output_tokens: int
    sonnet_input_tokens: int
    sonnet_output_tokens: int

    @property
    def total_usd(self) -> float:
        return (
            self.haiku_input_tokens * HAIKU_IN
            + self.haiku_output_tokens * HAIKU_OUT
            + self.sonnet_input_tokens * SONNET_IN
            + self.sonnet_output_tokens * SONNET_OUT
        )

    def summary(self) -> str:
        return (
            f"  Haiku:  ~{self.haiku_input_tokens:,} in / {self.haiku_output_tokens:,} out\n"
            f"  Sonnet: ~{self.sonnet_input_tokens:,} in / {self.sonnet_output_tokens:,} out\n"
            f"  Estimated cost: ${self.total_usd:.3f}"
        )


def _chars_to_tokens(chars: int) -> int:
    """Rough approximation: 1 token ≈ 4 characters."""
    return max(1, chars // 4)


def estimate_cost(scan) -> CostEstimate:
    """
    Rough cost estimate based on repo scan data, before any API calls.

    Pipeline:
    - Phase 1: Haiku folder summaries — reads all non-key files in chunks
    - Phase 2: Sonnet audit — folder summaries + key files in
    - Phase 3: Sonnet handoff — same input
    - Phase 4: Sonnet simple rewrites — audit.md + handoff.md in
    """
    # Estimate key file content size
    key_content_chars = sum(len(v) for v in scan.key_file_contents.values())

    # Estimate non-key file content (will be read and summarized by Haiku)
    key_paths = set(scan.key_file_contents.keys())
    other_files = [f for f in scan.all_files if f.rel not in key_paths]
    other_chars = min(sum(f.size for f in other_files), 500_000)  # cap at 500k chars

    # Phase 1: Haiku reads other files for folder summaries
    # In: file chunks; Out: ~150 tokens per dir summary, estimate ~30 dirs
    num_dirs = max(1, len(scan.folder_files))
    haiku_in = _chars_to_tokens(other_chars)
    haiku_out = num_dirs * 200  # ~200 tokens per folder summary

    # Phase 2 + 3: Sonnet audit + handoff
    # In: key files + folder summaries; Out: ~2000 tokens per doc × 2
    sonnet_analysis_in = _chars_to_tokens(key_content_chars) + haiku_out * 2
    sonnet_analysis_out = 4_000  # audit + handoff combined

    # Phase 4: Sonnet simple rewrites
    # In: audit.md + handoff.md (output of phases 2+3); Out: same length
    sonnet_rewrite_in = sonnet_analysis_out
    sonnet_rewrite_out = sonnet_analysis_out

    return CostEstimate(
        haiku_input_tokens=haiku_in,
        haiku_output_tokens=haiku_out,
        sonnet_input_tokens=sonnet_analysis_in + sonnet_rewrite_in,
        sonnet_output_tokens=sonnet_analysis_out + sonnet_rewrite_out,
    )
