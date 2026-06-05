"""
Robust statistics for the behavioral detector.

Uses median + MAD (median absolute deviation) rather than mean + std, because
the outliers we hunt would otherwise inflate the spread and hide themselves
(the 'masking' failure mode).
"""


def median(xs):
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def robust_z(vals):
    """Modified z-scores using median + MAD (Iglewicz-Hoaglin).

    Falls back to mean-absolute-deviation when MAD == 0 (which happens whenever
    most entities share a value, e.g. nearly everyone has zero failures). The
    0.6745 and 1.2533 constants rescale MAD/MeanAD to be comparable to a
    std-dev, so scores stay readable in 'sigma' units.
    Returns ({key: z}, median-used-as-the-normal-reference).
    """
    xs = list(vals.values())
    med = median(xs)
    devs = [abs(x - med) for x in xs]
    mad = median(devs)
    if mad > 0:
        scale = mad / 0.6745
    else:
        meanad = sum(devs) / len(devs)
        scale = 1.2533 * meanad
    z = {k: (0.0 if scale == 0 else (v - med) / scale) for k, v in vals.items()}
    return z, med


def is_http_error(code):
    return isinstance(code, int) and code >= 400
