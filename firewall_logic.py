# firewall_logic.py
import pandas as pd
from policyanalyzer import Policy, PolicyAnalyzer, Packet

# Define constants and helper functions
DEF_GEN = """A rule (Y) is a generalization of a preceding rule (X) if they
have different actions, and if rule (Y) can match all the packets that
match rule (X)."""

DEF_RXD = """A rule (X) is redundant if it performs the same action on the
same packets as a following rule (Y), and if rule (Y) can match all the packets
that match rule (X), except when there is an intermidate rule (Z)
that relates to (X) but with different action."""

DEF_RYD = """A rule (Y) is redundant if it performs the same action on the
same packets as a preceding rule (X), and if rule (X) can match all the packets
that match rule (Y)."""

DEF_SHD = """A rule (Y) is shadowed by a previous rule (X) if the they have
different actions, and if rule (X) matches all the packets that match rule (Y),
such that the rule (Y) will never be reached."""

DEF_COR = """Two rules (X) and (Y) are correlated if they have different
actions, and rule (X) matches some packets that match rule (Y) and
rule (Y) matches some packets that match rule (X)."""

desc = {
    "GEN": {
        "short": "Generalization",
        "long": "generalizes",
        "rec": "No change is required.",
        "def": DEF_GEN,
    },
    "SHD": {
        "short": "Shadowing",
        "long": "is shadowed by",
        "rec": "Move rule Y before X.",
        "def": DEF_SHD,
    },
    "COR": {
        "short": "Corrolation",
        "long": "corrolates with",
        "rec": "Verify correctness by sudying the effect of flipping the order of the two rules.",
        "def": DEF_COR,
    },
    "RXD": {
        "short": "Redundancy X",
        "long": "is a superset of",
        "rec": "Remove rule X.",
        "def": DEF_RXD,
    },
    "RYD": {
        "short": "Redundancy Y",
        "long": "is a subset of",
        "rec": "Remove rule Y",
        "def": DEF_RYD,
    },
}

def auto_optimize_rules(original_df, anom_dict):
    """Automatically optimizes firewall rules by resolving shadowing and redundancies."""
    rules = original_df.copy()
    modified = False

    # Process Shadowing (SHD) by moving Y before X
    shd_changes = []
    for y_rule_str in anom_dict:
        y_rule = int(y_rule_str)
        for x_rule_str, acode in anom_dict[y_rule_str].items():
            if acode == 'SHD':
                x_rule = int(x_rule_str)
                shd_changes.append((y_rule, x_rule))

    # Sort SHD changes by descending Y to process higher indices first
    for y_rule, x_rule in sorted(shd_changes, key=lambda x: -x[0]):
        if y_rule < len(rules) and x_rule < len(rules):
            rule_to_move = rules.iloc[y_rule:y_rule+1].copy()
            rules = pd.concat([rules.iloc[:y_rule], rules.iloc[y_rule+1:]]).reset_index(drop=True)
            insert_pos = x_rule if x_rule < y_rule else x_rule - 1
            rules = pd.concat([rules.iloc[:insert_pos], rule_to_move, rules.iloc[insert_pos:]]).reset_index(drop=True)
            modified = True

    # Process Redundancies (RXD and RYD)
    redundant_indices = set()
    for y_rule_str in anom_dict:
        y_rule = int(y_rule_str)
        for x_rule_str, acode in anom_dict[y_rule_str].items():
            if acode == 'RXD':
                redundant_indices.add(int(x_rule_str))
            elif acode == 'RYD':
                redundant_indices.add(int(y_rule_str))

    # Delete redundant rules in reverse order
    for idx in sorted(redundant_indices, reverse=True):
        if idx < len(rules):
            rules = rules.drop(rules.index[idx]).reset_index(drop=True)
            modified = True

    return rules if modified else original_df

def to_dict(rel_dict):
    """Convert anomalies lists to dictionary."""
    my_dict = {}
    for r_item in rel_dict:
        sub_dict = {}
        for i in rel_dict[r_item]:
            sub_dict[i[0]] = str(i[1])
        my_dict[r_item] = sub_dict
    return my_dict

def analyze_rules(rules_df):
    """Analyze rules and return anomalies."""
    policies = [Policy(**r) for r in rules_df.to_dict('records')]
    analyzer = PolicyAnalyzer(policies)
    anom = analyzer.get_anomalies()
    return to_dict(anom)

class Packet:
    def __init__(self, protocol, src, s_port, dst, d_port):
        self.protocol = protocol
        self.src = src
        self.s_port = s_port
        self.dst = dst
        self.d_port = d_port