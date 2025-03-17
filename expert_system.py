import pandas as pd
import ipaddress

class FirewallExpertSystem:
    def __init__(self):
        self.knowledge_base = {
            'SHD': {
                'condition': self._is_shadowed,
                'action': self._move_rule
            },
            'RXD': {
                'condition': self._is_redundant,
                'action': self._remove_rule
            },
            'RYD': {
                'condition': self._is_redundant,
                'action': self._remove_rule
            },
            'COR': {
                'condition': self._is_correlated,
                'action': self._flag_for_review
            }
        }

    def analyze_rules(self, rules_df, anomalies_dict):
        """Main analysis and optimization method"""
        optimized_rules = rules_df.copy()
        changes = []

        # Process all detected anomalies
        for y_rule_str in anomalies_dict:
            y_rule = int(y_rule_str)
            for x_rule_str, anomaly_type in anomalies_dict[y_rule_str].items():
                x_rule = int(x_rule_str)
                if anomaly_type in self.knowledge_base:
                    condition_met = self.knowledge_base[anomaly_type]['condition'](optimized_rules, x_rule, y_rule)
                    if condition_met:
                        optimized_rules = self.knowledge_base[anomaly_type]['action'](optimized_rules, x_rule, y_rule)
                        changes.append(f"Applied {anomaly_type} resolution between rules {x_rule} and {y_rule}")

        return optimized_rules, changes

    # Condition Checkers
    def _is_shadowed(self, df, x, y):
        """Check if earlier rule (x) is shadowed by later rule (y)"""
        if x >= len(df) or y >= len(df) or x < 0 or y < 0:
            return False
        rule_x = df.iloc[x]
        rule_y = df.iloc[y]
        return (rule_x['action'] != rule_y['action'] and 
                self._is_superset(rule_y, rule_x))

    def _is_redundant(self, df, x, y):
        """Check if rule x or y is redundant (superset/subset) regardless of action"""
        if x >= len(df) or y >= len(df) or x < 0 or y < 0:
            return False
        rule_x = df.iloc[x]
        rule_y = df.iloc[y]
        return (self._is_superset(rule_x, rule_y) or 
                self._is_superset(rule_y, rule_x))

    def _is_correlated(self, df, x, y):
        """Check if rules are correlated (partial overlap, different actions)"""
        if x >= len(df) or y >= len(df) or x < 0 or y < 0:
            return False
        rule_x = df.iloc[x]
        rule_y = df.iloc[y]
        return (rule_x['action'] != rule_y['action'] and
                self._partial_overlap(rule_x, rule_y))

    # Action Methods
    def _move_rule(self, df, x, y):
        """Move later rule (y) before earlier rule (x)"""
        rule_to_move = df.iloc[y:y+1]
        df = df.drop(index=y).reset_index(drop=True)
        insert_pos = x if x < y else x - 1
        return pd.concat([df.iloc[:insert_pos], rule_to_move, df.iloc[insert_pos:]]).reset_index(drop=True)

    def _remove_rule(self, df, x, y):
        """Remove redundant rule (prioritize broader rule)"""
        rule_x = df.iloc[x]
        rule_y = df.iloc[y]
        if self._is_superset(rule_x, rule_y):
            return df.drop(index=y).reset_index(drop=True)
        else:
            return df.drop(index=x).reset_index(drop=True)

    def _flag_for_review(self, df, x, y):
        """Flag correlated rules for manual review"""
        df.loc[x, 'needs_review'] = True
        df.loc[y, 'needs_review'] = True
        return df

    # Helper Methods
    def _is_superset(self, rule_a, rule_b):
        """Check if rule_a matches all packets of rule_b"""
        return (self._network_contains(rule_a['src'], rule_b['src']) and
                self._network_contains(rule_a['dst'], rule_b['dst']) and
                self._port_contains(rule_a['d_port'], rule_b['d_port']) and
                (rule_a['protocol'] == rule_b['protocol'] or rule_a['protocol'] == 'any'))

    def _partial_overlap(self, rule_a, rule_b):
        """Check if rules have overlapping but non-contained criteria"""
        src_overlap = self._network_overlap(rule_a['src'], rule_b['src'])
        dst_overlap = self._network_overlap(rule_a['dst'], rule_b['dst'])
        port_overlap = self._port_overlap(rule_a['d_port'], rule_b['d_port'])
        return src_overlap and dst_overlap and port_overlap

    def _network_contains(self, net_a, net_b):
        """Check if network A contains network B"""
        if net_a == '0.0.0.0/0': return True
        if net_b == '0.0.0.0/0': return False
        return ipaddress.ip_network(net_a).supernet_of(ipaddress.ip_network(net_b))

    def _network_overlap(self, net_a, net_b):
        """Check if networks overlap"""
        n1 = ipaddress.ip_network(net_a)
        n2 = ipaddress.ip_network(net_b)
        return n1.overlaps(n2)

    def _port_contains(self, ports_a, ports_b):
        """Check if ports_a contains ports_b"""
        if 'any' in ports_a: return True
        if 'any' in ports_b: return False
        a_ports = set(ports_a.split(','))
        b_ports = set(ports_b.split(','))
        return a_ports.issuperset(b_ports)

    def _port_overlap(self, ports_a, ports_b):
        """Check if port ranges overlap"""
        if 'any' in ports_a or 'any' in ports_b: return True
        a_ports = set(ports_a.split(','))
        b_ports = set(ports_b.split(','))
        return not a_ports.isdisjoint(b_ports)

    def _get_explanation_text(self, anomaly_type, x, y):
        explanations = {
            'SHD': f"Rule {x} is shadowed by broader rule {y}. Moved rule {y} before {x}.",
            'RXD': f"Rule {y} is redundant due to rule {x}. Removed rule {y}.",
            'RYD': f"Rule {x} is redundant due to rule {y}. Removed rule {x}.",
            'COR': f"Rules {x} and {y} have conflicting actions. Manual review required."
        }
        return explanations.get(anomaly_type, "Optimization performed.")