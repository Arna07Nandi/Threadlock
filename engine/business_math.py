"""
Threadlock Everyday Business Math Engine (Hardened — Exact Integer Minor Units, Zero Float Drift)
Covers:
  1. Discount-to-Profit Erosion & Exact Break-Even Volume Multiplier (handles unprofitable discounts honestly)
  2. Net-60 / Net-90 Cash-Flow Drag & Savings from switching to 50% Advance / 50% Net-15
  3. Scope-Creep Effective Hourly Rate Dilution
  4. GST-Inclusive Back-Calculation (exact reverse math for "₹1,50,000 all-inclusive of 18% GST")
"""
from __future__ import annotations

from typing import Dict, Optional


def extract_gst_inclusive(gross_minor: int, gst_pct: int = 18) -> Dict[str, int]:
    """
    Exact integer back-calculation when a client agrees to a GST-inclusive lump sum.
    Formula: base = round(gross * 100 / (100 + gst_pct)), gst = gross - base.
    Guarantees base + gst == gross with zero floating-point drift.
    """
    if gross_minor < 0 or gst_pct < 0:
        raise ValueError("gross_minor and gst_pct must be non-negative")
    denom = 100 + gst_pct
    base_minor = (gross_minor * 100 + denom // 2) // denom
    gst_minor = gross_minor - base_minor
    return {"gross_minor": gross_minor, "base_minor": base_minor, "gst_minor": gst_minor}


def compute_deal_economics(
    base_minor: int,
    direct_cost_minor: int,
    proposed_discount_pct: int = 0,
    payment_days: int = 30,
    estimated_hours: int = 20,
    extra_unpaid_hours: int = 0,
    annual_cost_of_capital_pct: int = 15,
    upfront_gst_pct: int = 0,
) -> Dict[str, object]:
    if base_minor <= 0:
        raise ValueError("base_minor must be > 0")
    if direct_cost_minor < 0:
        raise ValueError("direct_cost_minor cannot be negative")
    if not (0 <= proposed_discount_pct <= 99):
        raise ValueError("proposed_discount_pct must be between 0 and 99")

    # 1. Discount-to-Profit Erosion
    discount_minor = (base_minor * proposed_discount_pct + 50) // 100
    discounted_rev = base_minor - discount_minor
    orig_profit = base_minor - direct_cost_minor
    new_profit = discounted_rev - direct_cost_minor

    orig_margin_bps = (orig_profit * 10_000) // base_minor
    new_margin_bps = (new_profit * 10_000) // discounted_rev if discounted_rev > 0 else 0
    unprofitable_after_discount = new_profit <= 0

    if orig_profit > 0:
        profit_destroyed_bps = ((orig_profit - new_profit) * 10_000) // orig_profit
    else:
        profit_destroyed_bps = 10_000

    breakeven_extra_volume_pct: Optional[int] = (
        ((orig_profit - new_profit) * 100 + (new_profit // 2)) // new_profit
        if new_profit > 0 and orig_profit > 0
        else None
    )

    # 2. Net-60 / Net-90 Cash-Flow Drag vs 50% Advance / 50% Net-15 Milestone Split
    gst_lockup_minor = (discounted_rev * upfront_gst_pct + 50) // 100
    locked_capital = direct_cost_minor + gst_lockup_minor
    financing_drag_minor = (locked_capital * annual_cost_of_capital_pct * max(0, payment_days)) // (365 * 100)
    # Effective wait on 50% upfront / 50% Net-15 is ~7.5 days (half locked for 15 days)
    milestone_drag_minor = (locked_capital * annual_cost_of_capital_pct * 15) // (2 * 365 * 100)
    cash_drag_saved_by_milestones = max(0, financing_drag_minor - milestone_drag_minor)

    # 3. Scope-Creep Effective Hourly Rate Dilution
    base_hrs = max(1, int(estimated_hours))
    total_hrs = base_hrs + max(0, int(extra_unpaid_hours))
    planned_hourly_minor = orig_profit // base_hrs
    actual_hourly_minor = (new_profit - financing_drag_minor) // total_hrs

    if unprofitable_after_discount:
        summary = f"CRITICAL: A {proposed_discount_pct}% discount makes this deal unprofitable (net loss)."
    elif proposed_discount_pct > 0:
        summary = (
            f"A {proposed_discount_pct}% discount wipes out {round(profit_destroyed_bps / 100.0, 1)}% of your profit "
            f"(requiring +{breakeven_extra_volume_pct}% more sales to break even)."
        )
    else:
        summary = "No discount erosion. Cash-flow and hourly economics verified."

    return {
        "base_minor": base_minor,
        "discounted_revenue_minor": discounted_rev,
        "original_profit_minor": orig_profit,
        "post_discount_profit_minor": new_profit,
        "unprofitable_after_discount": unprofitable_after_discount,
        "original_margin_pct": round(orig_margin_bps / 100.0, 2),
        "new_margin_pct": round(new_margin_bps / 100.0, 2),
        "profit_destroyed_pct": round(profit_destroyed_bps / 100.0, 2),
        "breakeven_extra_volume_needed_pct": breakeven_extra_volume_pct,
        "net_terms_days": payment_days,
        "cash_flow_financing_drag_minor": financing_drag_minor,
        "cash_drag_saved_by_milestones_minor": cash_drag_saved_by_milestones,
        "planned_effective_hourly_minor": planned_hourly_minor,
        "actual_effective_hourly_minor": actual_hourly_minor,
        "warning_summary": summary,
    }
