"""
Log Analyzer for Brute-Force Detection
=======================================
Parses SSH auth logs and Apache/Nginx access logs, detects brute-force attacks
using a sliding-window algorithm, and generates matplotlib/seaborn visualizations.

Usage (CLI):
    python analyzer.py ssh
    python analyzer.py apache
"""

import re
import base64
import io
from datetime import datetime, timedelta

import pandas as pd
import matplotlib
matplotlib.use('Agg')           # Non-interactive backend — must be set before pyplot
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import Patch
import seaborn as sns
import numpy as np


# ─── Regex Patterns ───────────────────────────────────────────────────────────

# Handles both:
#   Failed password for [invalid user] <user> from <ip>
#   Invalid user <user> from <ip>
SSH_FAILED_RE = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?:Failed password for (?:invalid user )?|Invalid user )(\S+)\s+from\s+'
    r'(\d{1,3}(?:\.\d{1,3}){3})',
    re.MULTILINE
)

# Apache / Nginx Combined Log Format
APACHE_RE = re.compile(
    r'^(\d{1,3}(?:\.\d{1,3}){3})\s+-\s+\S+\s+\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+[+-]\d{4}\]\s+'
    r'"(?:POST|GET|PUT)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d{3})',
    re.MULTILINE
)

LOGIN_PATH_RE = re.compile(
    r'login|signin|wp-login|wp-admin|admin|auth(?:enticate)?|account|session',
    re.IGNORECASE
)


# ─── Colour Palette ───────────────────────────────────────────────────────────

PURPLE      = '#9333ea'
PINK        = '#ec4899'
LIGHT_PUR   = '#a78bfa'
LIGHT_PINK  = '#f9a8d4'
BG_DARK     = '#0a0a1a'
CARD_BG     = '#0d0d1f'
GRID_COL    = '#1e1b4b'
TEXT_COL    = '#e2e8f0'
MUTED_COL   = '#a78bfa'


# ─── Parsers ──────────────────────────────────────────────────────────────────

def parse_ssh_logs(log_text: str) -> list:
    """Extract failed SSH login entries from auth.log format."""
    entries = []
    year = datetime.now().year

    for line in log_text.splitlines():
        m = SSH_FAILED_RE.search(line)
        if not m:
            continue
        try:
            # Normalise multi-space (e.g. "Oct  3" → "Oct 3")
            ts_raw = re.sub(r'\s+', ' ', m.group(1).strip())
            ts = datetime.strptime(f"{year} {ts_raw}", "%Y %b %d %H:%M:%S")
            entries.append({
                'timestamp': ts,
                'ip':        m.group(3),
                'user':      m.group(2),
                'log_type':  'ssh',
                'event':     'failed_login',
                'raw':       line.strip(),
            })
        except ValueError:
            continue

    return entries


def parse_apache_logs(log_text: str) -> list:
    """Extract failed auth attempts from Apache/Nginx Combined Log Format."""
    entries = []

    for line in log_text.splitlines():
        m = APACHE_RE.search(line)
        if not m:
            continue
        ip      = m.group(1)
        ts_str  = m.group(2)
        path    = m.group(3)
        status  = int(m.group(4))

        # Only flag 401/403 responses on login-related URLs
        if status in (401, 403) and LOGIN_PATH_RE.search(path):
            try:
                ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
                entries.append({
                    'timestamp': ts,
                    'ip':        ip,
                    'user':      path,
                    'log_type':  'apache',
                    'event':     'failed_login',
                    'status':    status,
                    'raw':       line.strip(),
                })
            except ValueError:
                continue

    return entries


# ─── Detection Engine ─────────────────────────────────────────────────────────

def _sliding_window_max(times: list, window_secs: int) -> int:
    """O(n) sliding-window: max events within any window_secs interval."""
    if not times:
        return 0
    times = sorted(times)
    max_count = j = 0
    for i in range(len(times)):
        if j < i:
            j = i
        while j < len(times) and (times[j] - times[i]).total_seconds() <= window_secs:
            j += 1
        max_count = max(max_count, j - i)
    return max_count


def _severity(max_in_window: int) -> str:
    if max_in_window >= 20:
        return 'CRITICAL'
    if max_in_window >= 10:
        return 'HIGH'
    return 'MEDIUM'


def detect_brute_force(entries: list, threshold: int = 5, window_secs: int = 60) -> dict:
    """
    Core detection logic.

    Args:
        entries        : parsed log records (list of dicts)
        threshold      : min events in a window to flag an IP
        window_secs    : sliding window duration (seconds)

    Returns dict with:
        flagged_ips    : list of flagged IP summaries
        stats          : aggregate statistics
        charts         : dict of chart_name → base64 PNG string
        timeline_data  : 5-min bucket counts for sparklines
    """
    if not entries:
        return {
            'flagged_ips':   [],
            'stats':         {'total_attempts': 0, 'unique_ips': 0,
                              'flagged_count': 0, 'time_span': 'N/A'},
            'charts':        {},
            'timeline_data': [],
        }

    df = pd.DataFrame(entries)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)

    # ── Per-IP analysis ──────────────────────────────────────────────────────
    flagged_ips = []
    for ip, grp in df.groupby('ip'):
        times = sorted(np.array(grp['timestamp'].dt.to_pydatetime()).tolist())
        total = len(times)
        max_win = _sliding_window_max(times, window_secs)
        first, last = times[0], times[-1]
        dur_min = (last - first).total_seconds() / 60

        if max_win >= threshold:
            flagged_ips.append({
                'ip':               ip,
                'total_attempts':   total,
                'max_in_window':    max_win,
                'first_seen':       first.strftime('%Y-%m-%d %H:%M:%S'),
                'last_seen':        last.strftime('%Y-%m-%d %H:%M:%S'),
                'duration_minutes': round(dur_min, 1),
                'rate_per_minute':  round(total / max(dur_min, 0.1), 1),
                'severity':         _severity(max_win),
            })

    flagged_ips.sort(key=lambda x: x['total_attempts'], reverse=True)

    # ── Aggregate stats ──────────────────────────────────────────────────────
    stats = {
        'total_attempts': int(len(df)),
        'unique_ips':     int(df['ip'].nunique()),
        'flagged_count':  len(flagged_ips),
        'time_span':      (
            f"{df['timestamp'].min().strftime('%Y-%m-%d %H:%M')} → "
            f"{df['timestamp'].max().strftime('%Y-%m-%d %H:%M')}"
        ),
    }

    # ── Timeline (5-min buckets) ─────────────────────────────────────────────
    ts_series = df.set_index('timestamp').resample('5min').size()
    timeline_data = [
        {'time': t.strftime('%H:%M'), 'count': int(c)}
        for t, c in ts_series.items()
    ]

    # ── Generate charts ──────────────────────────────────────────────────────
    _apply_theme()
    charts = {}
    charts['timeline'] = _chart_timeline(df)
    if flagged_ips:
        charts['top_ips'] = _chart_top_ips(flagged_ips)
    hm = _chart_heatmap(df)
    if hm:
        charts['heatmap'] = hm

    return {
        'flagged_ips':   flagged_ips,
        'stats':         stats,
        'charts':        charts,
        'timeline_data': timeline_data,
    }


# ─── Chart Helpers ────────────────────────────────────────────────────────────

def _apply_theme():
    plt.rcParams.update({
        'figure.facecolor':  BG_DARK,
        'axes.facecolor':    CARD_BG,
        'axes.edgecolor':    '#2d1b69',
        'axes.labelcolor':   MUTED_COL,
        'xtick.color':       MUTED_COL,
        'ytick.color':       MUTED_COL,
        'text.color':        TEXT_COL,
        'grid.color':        GRID_COL,
        'grid.alpha':        0.5,
        'axes.titlecolor':   LIGHT_PINK,
        'font.family':       'DejaVu Sans',
        'font.size':         10,
    })


def _fig_to_b64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight', dpi=130,
                facecolor=fig.get_facecolor(), edgecolor='none')
    buf.seek(0)
    data = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)
    return data


def _chart_timeline(df) -> str:
    """Area + line chart: failed attempts over time in 5-min buckets."""
    ts_counts = df.set_index('timestamp').resample('5min').size()
    fig, ax = plt.subplots(figsize=(12, 4))

    if len(ts_counts) > 1:
        x = ts_counts.index.to_pydatetime()
        y = ts_counts.values.astype(float)
        ax.fill_between(x, y, alpha=0.22, color=PURPLE)
        ax.plot(x, y, color=PINK, linewidth=2.5, marker='o',
                markersize=5, markerfacecolor=PURPLE,
                markeredgecolor=PINK, markeredgewidth=1.5)
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
        ax.xaxis.set_major_locator(mdates.AutoDateLocator())
        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right', fontsize=8)
    elif len(ts_counts) == 1:
        ax.bar([0], ts_counts.values, color=PURPLE, width=0.4)
        ax.set_xticks([0])
        ax.set_xticklabels([ts_counts.index[0].strftime('%H:%M')])

    ax.set_title('Failed Login Attempts Over Time (5-min buckets)',
                 fontsize=13, fontweight='bold', pad=12)
    ax.set_xlabel('Time', fontsize=10)
    ax.set_ylabel('Attempts', fontsize=10)
    ax.grid(True, linestyle='--', alpha=0.4)
    for sp in ax.spines.values():
        sp.set_color('#2d1b69')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout(pad=1.5)
    return _fig_to_b64(fig)


def _chart_top_ips(flagged_ips: list) -> str:
    """Horizontal bar chart: top attacking IPs coloured by severity."""
    top   = flagged_ips[:15]
    ips    = [x['ip'] for x in top]
    counts = [x['total_attempts'] for x in top]
    sevs   = [x.get('severity', 'MEDIUM') for x in top]

    colour_map = {'CRITICAL': PINK, 'HIGH': PURPLE, 'MEDIUM': LIGHT_PUR}
    bar_cols   = [colour_map.get(s, LIGHT_PUR) for s in sevs]

    fig_h = max(4, len(ips) * 0.65 + 1.5)
    fig, ax = plt.subplots(figsize=(10, fig_h))

    bars = ax.barh(range(len(ips)), counts, color=bar_cols,
                   edgecolor='#2d1b69', linewidth=0.5, height=0.6)
    ax.set_yticks(range(len(ips)))
    ax.set_yticklabels(ips, fontsize=9)
    ax.invert_yaxis()

    max_c = max(counts) if counts else 1
    for bar, cnt in zip(bars, counts):
        ax.text(bar.get_width() + max_c * 0.015,
                bar.get_y() + bar.get_height() / 2,
                str(cnt), va='center', ha='left',
                color=TEXT_COL, fontsize=9)

    ax.set_title('Top Attacking IPs — Total Failed Attempts',
                 fontsize=13, fontweight='bold', pad=12)
    ax.set_xlabel('Total Failed Attempts', fontsize=10)
    ax.set_xlim(right=max_c * 1.18)
    ax.grid(True, axis='x', linestyle='--', alpha=0.4)
    ax.legend(
        handles=[
            Patch(facecolor=PINK,     label='CRITICAL  (≥20 / window)'),
            Patch(facecolor=PURPLE,   label='HIGH      (≥10 / window)'),
            Patch(facecolor=LIGHT_PUR, label='MEDIUM   (≥5  / window)'),
        ],
        loc='lower right', framealpha=0.3,
        facecolor=CARD_BG, edgecolor='#2d1b69', fontsize=8,
    )
    for sp in ax.spines.values():
        sp.set_color('#2d1b69')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout(pad=1.5)
    return _fig_to_b64(fig)


def _chart_heatmap(df) -> str | None:
    """Heatmap: attack intensity by hour of day vs. date."""
    df2 = df.copy()
    df2['hour'] = df2['timestamp'].dt.hour
    df2['day']  = df2['timestamp'].dt.strftime('%a %m-%d')

    pivot = df2.groupby(['day', 'hour']).size().unstack(fill_value=0)
    if pivot.empty:
        return None

    # Fill missing hours
    for h in range(24):
        if h not in pivot.columns:
            pivot[h] = 0
    pivot = pivot.reindex(sorted(pivot.columns), axis=1)

    cmap = LinearSegmentedColormap.from_list(
        'brute', [BG_DARK, '#3b0764', PURPLE, PINK, '#ff006e']
    )
    fig_h = max(3, len(pivot) * 0.75 + 1.5)
    fig, ax = plt.subplots(figsize=(16, fig_h))

    sns.heatmap(
        pivot, ax=ax, cmap=cmap,
        linewidths=0.3, linecolor='#0a0a1a',
        annot=True, fmt='d',
        annot_kws={'size': 8, 'color': TEXT_COL},
        cbar_kws={'label': 'Attempts', 'shrink': 0.8},
    )
    ax.set_title('Attack Intensity Heatmap — Hour of Day vs Date',
                 fontsize=13, fontweight='bold', pad=12)
    ax.set_xlabel('Hour of Day (0–23)', fontsize=10)
    ax.set_ylabel('Date', fontsize=10)
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=0, fontsize=8)
    plt.setp(ax.yaxis.get_majorticklabels(), rotation=0, fontsize=8)

    cbar = ax.collections[0].colorbar
    if cbar:
        cbar.ax.yaxis.label.set_color(MUTED_COL)
        cbar.ax.tick_params(colors=MUTED_COL)

    fig.tight_layout(pad=1.5)
    return _fig_to_b64(fig)


# ─── Public API ───────────────────────────────────────────────────────────────

def analyze(log_text: str, log_type: str = 'auto',
            threshold: int = 5, window_secs: int = 60) -> dict:
    """
    Parse logs, detect brute-force attacks, and return a full analysis report.

    Args:
        log_text     : raw log file content
        log_type     : 'ssh' | 'apache' | 'auto'
        threshold    : failed-login count to flag an IP
        window_secs  : sliding window size (seconds)

    Returns:
        dict — flagged_ips, stats, charts (base64 PNG), timeline_data,
               log_type, entries_parsed
    """
    log_text = log_text.strip()
    if not log_text:
        return {
            'flagged_ips': [], 'stats': {}, 'charts': {},
            'timeline_data': [], 'log_type': log_type, 'entries_parsed': 0,
        }

    # Auto-detect format
    if log_type == 'auto':
        if re.search(r'sshd\[\d+\]', log_text) or 'Failed password' in log_text or 'Invalid user' in log_text:
            log_type = 'ssh'
        elif re.search(r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', log_text):
            log_type = 'apache'
        else:
            log_type = 'ssh'

    if log_type == 'ssh':
        entries = parse_ssh_logs(log_text)
    elif log_type == 'apache':
        entries = parse_apache_logs(log_text)
    else:
        entries = parse_ssh_logs(log_text) + parse_apache_logs(log_text)

    result = detect_brute_force(entries, threshold=threshold, window_secs=window_secs)
    result['log_type']      = log_type
    result['entries_parsed'] = len(entries)
    return result


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import os, sys

    script_dir = os.path.dirname(os.path.abspath(__file__))
    arg = (sys.argv[1] if len(sys.argv) > 1 else 'ssh').lower()
    log_path = os.path.join(script_dir, 'sample_logs',
                            'ssh_auth.log' if arg == 'ssh' else 'apache_access.log')

    print(f"Reading  : {log_path}")
    with open(log_path, 'r') as f:
        text = f.read()

    print(f"Analyzing: {arg} logs …")
    r = analyze(text, log_type=arg)

    SEP = '=' * 55
    print(f"\n{SEP}")
    print(f"  Analysis Complete — {arg.upper()} Logs")
    print(SEP)
    print(f"  Entries parsed   : {r['entries_parsed']}")
    print(f"  Total attempts   : {r['stats'].get('total_attempts', 0)}")
    print(f"  Unique IPs       : {r['stats'].get('unique_ips', 0)}")
    print(f"  Flagged IPs      : {r['stats'].get('flagged_count', 0)}")
    span = r['stats'].get('time_span', 'N/A').replace('\u2192', '->')
    print(f"  Time span        : {span}")
    print(f"\n  Flagged IPs:")
    for d in r['flagged_ips']:
        print(f"    [{d['severity']:8s}] {d['ip']:20s} "
              f"{d['total_attempts']:4d} total  "
              f"max {d['max_in_window']} in window")
    print(f"\n  Charts           : {list(r['charts'].keys())}")
    print(SEP + '\n')
