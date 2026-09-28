"""Pure decision rules from docs/v1.15-protocol.md (accepted revision 05035d5).

This is the numerical component, not an evidence importer or activation command.
Callers must supply already selected/qualified observations and retain exclusions.
They must enforce source/build hashes, exact target/CPU/feature cells, first-attempt
scheduled selection, complete target inventories and fixed-window completion.
In particular, ``covered`` below is a cell-level coverage result, not a final
study verdict before all 42 dates elapse. No historical/D1 data qualify as the
fresh study cohort merely by passing these arithmetic functions.
"""
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal, ROUND_CEILING, localcontext
import re

RULE_VERSION = '05035d5-v1'
CURRENT_BOUND = Decimal('0.55')
GRID = Decimal('0.05')
FLOOR = Decimal('0.20')
CONTEXT = ('full', 'filtered', 'sham')
LEAKY = ('modest-left', 'modest-right', 'gross-left', 'gross-right')


def normalize_cpu(value):
    """Do not collapse model numbers, case, or nonliteral trademark spellings."""
    if not isinstance(value, str):
        raise ValueError('CPU model must be present')
    result = ' '.join(value.replace('(R)', '').replace('(TM)', '').split())
    if not result:
        raise ValueError('CPU model must be present')
    return result


def median_five(values):
    """Use exactly five signed five-decimal bench outputs, never gate-list rounding."""
    if not isinstance(values, (list, tuple)) or len(values) != 5:
        raise ValueError('exactly five values required')
    if any(not isinstance(x, str) or not re.fullmatch(r'[+-]?[0-9]+\.[0-9]{5}', x) for x in values):
        raise ValueError('finite five-decimal printed values required')
    # copy_abs avoids ambient decimal-context rounding of the original printed value.
    return sorted(Decimal(x).copy_abs() for x in values)[2]


def _dated_values(start, observations):
    if type(start) is not date:
        raise ValueError('window start must be a UTC date')
    end = start + timedelta(days=42)
    seen = set()
    rows = []
    for day, values in observations:
        if type(day) is not date or not start <= day < end:
            raise ValueError('observation outside the fixed 42 UTC dates')
        if day in seen:
            raise ValueError('duplicate date in an exact cell')
        seen.add(day)
        rows.append((day, median_five(values)))
    return sorted(rows)


def candidate_cell(start, observations):
    """Derive one of the four demoted-target cells from qualified observations.

    Input pairs are (UTC date, five printed signed tau strings), already grouped
    by the exact target/CPU/feature identity. An empty list is sparse evidence.
    Fanout is outside this fit and must retain its existing policy in the table.
    """
    rows = _dated_values(start, observations)
    halves = [sum(day < start + timedelta(days=21) for day, _ in rows),
              sum(day >= start + timedelta(days=21) for day, _ in rows)]
    result = dict(dates=len(rows), half_dates=halves, current_bound='0.55',
                  bound=None, q90=None, status=None)
    if any(x > CURRENT_BOUND for _, x in rows):
        result['status'] = 'investigation-required'
    elif len(rows) < 20 or min(halves) < 5:
        result['status'] = 'insufficient-calibration'
    else:
        q90 = sorted(x for _, x in rows)[(9 * len(rows) + 9) // 10 - 1]
        # Values here are <=0.55, so this precision exactly covers every operation.
        with localcontext() as ctx:
            ctx.prec = 28
            bound = max(FLOOR, GRID * (2 * q90 / GRID).to_integral_value(rounding=ROUND_CEILING))
        result['q90'] = str(q90)
        result['fitted_bound'] = format(bound, '.2f')
        if bound >= CURRENT_BOUND:
            result.update(status='unchanged', bound='0.55')
        elif any(x > bound for _, x in rows):
            result['status'] = 'candidate-rejected'
        else:
            result.update(status='proposed-tightening', bound=format(bound, '.2f'))
    return result


def _changed_bound(value):
    if not isinstance(value, str) or not re.fullmatch(r'0\.[0-9]{2}', value):
        raise ValueError('a frozen tightening bound is required')
    bound = Decimal(value)
    if not FLOOR <= bound < CURRENT_BOUND or int(value[2:]) % 5:
        raise ValueError('bound must be on the 0.05 grid from 0.20 through 0.50')
    return bound


@dataclass(frozen=True)
class Measurement:
    """One independently qualified control measurement, not an entire job.

    qualified is true only after the caller verifies build/control identity,
    CPU/image metadata, sample budget, pass identities and required target set.
    Missing/mismatched evidence must set it false; a process exit code alone is
    insufficient. Numerical validity and liveness are checked here as well.
    """
    tau: list[str]
    negative_control: list[str]
    qualified: bool

    def usable_median(self):
        if self.qualified is not True:
            return None
        try:
            value = median_five(self.tau)
            median_five(self.negative_control)  # Validate every printed value first.
        except ValueError:
            return None
        if any(Decimal(x).copy_abs() <= 1 for x in self.negative_control):
            return None
        return value


def control_job(bound, measurements):
    """Apply section 5's partial-evidence ordering for one changed cell/job.

    Missing keys mean missing measurements. A missing measurement cannot erase
    an already usable context breach or (with passing context) a usable escape.
    The caller counts covered jobs only once per distinct UTC date and verifies
    control scheduling, subgroup coverage and dispatch/time budget separately.
    """
    bound = _changed_bound(bound)
    if measurements.keys() - set(CONTEXT + LEAKY):
        raise ValueError('unknown control variant')
    values = {}
    for name in CONTEXT + LEAKY:
        measurement = measurements.get(name)
        if measurement is not None and not isinstance(measurement, Measurement):
            raise ValueError('expected a Measurement or missing evidence')
        values[name] = measurement.usable_median() if measurement is not None else None
    context_breaches = [name for name in CONTEXT if values[name] is not None and values[name] > bound]
    if context_breaches:
        status, reasons = 'rejected', ['context-breach:' + name for name in context_breaches]
    elif any(values[name] is None for name in CONTEXT):
        status, reasons = 'incomplete', ['unusable-context:' + name for name in CONTEXT if values[name] is None]
    else:
        escapes = [name for name in LEAKY if values[name] is not None and values[name] <= bound]
        if escapes:
            status, reasons = 'rejected', ['control-escape:' + name for name in escapes]
        elif any(values[name] is None for name in LEAKY):
            status, reasons = 'incomplete', ['unusable-control:' + name for name in LEAKY if values[name] is None]
        else:
            status, reasons = 'covered', []
    return dict(status=status, reasons=reasons,
                medians={name: str(x) if x is not None else None for name, x in values.items()})


def confirmation_cell(start, bound, observations):
    """Count qualified ordinary-run dates and all observed image/kernel pairs.

    Input rows are (UTC date, five printed tau strings, image version, kernel).
    Inputs must include all eligible observations for this frozen changed cell;
    excluding a failing or sparse subgroup is forbidden. Results are provisional
    until the enclosing evaluator verifies the entire 42-day window is complete.
    Control coverage and unresolved existing-gate breaches are separate inputs
    to the final table decision, never inferred from a quiet cell here.
    """
    bound = _changed_bound(bound)
    observations = list(observations)
    rows = _dated_values(start, [(day, values) for day, values, _, _ in observations])
    groups = defaultdict(set)
    for day, _, image, kernel in observations:
        if not isinstance(image, str) or not image.strip() or not isinstance(kernel, str) or not kernel.strip():
            raise ValueError('image version and kernel required for qualified evidence')
        groups[(image, kernel)].add(day)
    breaches = [day.isoformat() for day, x in rows if x > bound]
    status = ('rejected' if breaches else
              'insufficient-evidence' if len(rows) < 20 or any(len(days) < 3 for days in groups.values())
              else 'covered')
    return dict(status=status, dates=len(rows), breach_dates=breaches,
                subgroups=[dict(image_version=image, kernel=kernel, dates=len(days))
                           for (image, kernel), days in sorted(groups.items())])


def table_outcome(*, has_candidates, rejected, coverage_complete, unresolved_gate):
    """Section 7 precedence, called only after the required full window ends.

    coverage_complete must include every build/environment and ordinary/control
    coverage requirement across the whole frozen activation set. This helper
    does not establish those prerequisites or authorize activation itself.
    """
    if any(type(x) is not bool for x in (has_candidates, rejected, coverage_complete, unresolved_gate)):
        raise ValueError('explicit boolean table predicates required')
    if rejected:
        return 'rejected'
    if not has_candidates or not coverage_complete or unresolved_gate:
        return 'insufficient evidence'
    return 'eligible for activation review'
