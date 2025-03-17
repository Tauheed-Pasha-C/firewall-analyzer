from io import StringIO
import pandas as pd
import streamlit as st
st.set_page_config(layout="wide")
from firewall_logic import auto_optimize_rules, to_dict, desc
from policyanalyzer import Policy, PolicyAnalyzer, Packet
from expert_system import FirewallExpertSystem
class RuleOptimizerTrainer:
    def train_model(self, csv_path):
        # Placeholder for model training logic
        pass

if 'ml_mode' not in st.session_state:
    st.session_state.ml_mode = False

with st.sidebar:
    st.markdown("## Optimization Mode")
    mode = st.radio("Select mode:", 
                   ["Predefined Logic", "AI-Driven"], 
                   index=0 if not st.session_state.ml_mode else 1)
    
    st.session_state.ml_mode = (mode == "AI-Driven")

EXAMPLE_RULES = """
protocol,src,s_port,dst,d_port,action
tcp,140.192.37.20,any,0.0.0.0/0,HTTP,deny
tcp,140.192.37.0/24,any,0.0.0.0/0,"HTTP, HTTPS",accept
tcp,0.0.0.0/0,any,161.120.33.40,80,accept
tcp,140.192.37.0/24,any,161.120.33.40,80,deny
tcp,140.192.37.30,any,0.0.0.0/0,21,deny
tcp,140.192.37.0/24,any,0.0.0.0/0,21,accept
tcp,140.192.37.0/24,any,161.120.33.40,21,accept
tcp,0.0.0.0/0,any,0.0.0.0/0,any,deny
udp,140.192.37.0/24,any,161.120.33.40,DNS,accept
udp,0.0.0.0/0,any,161.120.33.40,53,accept
udp,140.192.38.0/24,any,161.120.35.0/24,any,accept
udp,0.0.0.0/0,any,0.0.0.0/0,any,deny
"""

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

TITLE = "Firewall Policy Analyzer"
ABOUT = """This app analyzes a set of firewall policies and detects common 
patterns and conflicts.\n
:warning: This is work in progress. Use at your own risk. :warning:"""
NO_RELATION = ":heavy_check_mark: No anomalies detected."
EXAMPLE_HELP = "Use built-in example file to demo the app."
SELECT_RULES = "Select rules to review relationships."
UPLOAD_FILE = "Upload a file"

packet_fields = ["protocol", "src", "s_port", "dst", "d_port"]
errors = ["SHD", "RYD", "RXD"]
warn = ["COR"]

if 'optimized' not in st.session_state:
    st.session_state.optimized = False

change_log = [] 


def color_erros(val):
    """Return style color for errors and warnnings"""

    fcolor = "red" if val in errors else "orange" if val in warn else None
    # bcolor = 'red' if val in errors else 'orange' if val in warn else None
    # style = f'background-color: {bcolor};' if bcolor else ''
    style = f"color: {fcolor};" if fcolor else ""
    return style


def convert_df(data_frame):
    """convert dataframe to csv"""

    return data_frame.to_csv(index=False).encode("utf-8")



# Manual Rule Input Section
# Manual Rule Input Section
st.sidebar.header("Manual Rule Input")
with st.sidebar.form(key="manual_rule_form"):
    st.write("Add a new rule manually:")
    protocol = st.text_input("Protocol (e.g., tcp, udp, icmp, any)", value="tcp", key="protocol")
    src = st.text_input("Source IP (e.g., 140.192.37.20)", value="0.0.0.0/0", key="src")
    s_port = st.text_input("Source Port (e.g., any, 80)", value="any", key="s_port")
    dst = st.text_input("Destination IP (e.g., 161.120.33.40)", value="0.0.0.0/0", key="dst")
    d_port = st.text_input("Destination Port (e.g., HTTP, 21)", value="any", key="d_port")
    action = st.text_input("Action (e.g., accept, deny)", value="accept", key="action")
    submit_manual_rule = st.form_submit_button("Add Rule")

# Initialize session state for manual rules if not already present
if "manual_rules" not in st.session_state:
    st.session_state.manual_rules = []

# Add the manually entered rule to the session state
if submit_manual_rule:
    new_rule = {
        "protocol": protocol,
        "src": src,
        "s_port": s_port,
        "dst": dst,
        "d_port": d_port,
        "action": action
    }
    st.session_state.manual_rules.append(new_rule)
    st.success("Rule added successfully!")


def get_matches(preader, analyzer):
    """Process packet logs with explicit column handling"""
    rule_nums = []
    rule_actions = []
    
    # Validate required columns
    required_cols = ["protocol", "src", "s_port", "dst", "d_port"]
    missing_cols = [col for col in required_cols if col not in preader.columns]
    if missing_cols:
        raise ValueError(f"Missing columns in packet logs: {missing_cols}")

    # Process each packet
    for _, row in preader.iterrows():
        try:
            packet = Packet(
                protocol=row["protocol"],
                src=row["src"],
                s_port=row["s_port"],
                dst=row["dst"],
                d_port=row["d_port"]
            )
        except KeyError as e:
            raise ValueError(f"Invalid packet format: {str(e)}")

        # Match against rules
        match = analyzer.get_first_match(packet)
        if match:
            rule_nums.append(str(match[0]))
            rule_actions.append(match[1].get_action())
        else:
            rule_nums.append("No Match")
            rule_actions.append("deny")  # Default action

    # Add results to DataFrame
    preader = preader.copy()
    preader["matched_rule"] = rule_nums
    preader["action"] = rule_actions
    return preader

# Function to move a row based on 'before' or 'after' selection
def move_row(df, from_idx, to_idx, position):
    df = df.copy()
    row = df.iloc[from_idx]
    df = df.drop(index=from_idx).reset_index(drop=True)

    if position == "before":
        df_top = df.iloc[:to_idx]
        df_bottom = df.iloc[to_idx:]
        df = pd.concat([df_top, pd.DataFrame([row]), df_bottom]).reset_index(drop=True)
    else:  # "after"
        df_top = df.iloc[: to_idx + 1]
        df_bottom = df.iloc[to_idx + 1 :]
        df = pd.concat([df_top, pd.DataFrame([row]), df_bottom]).reset_index(drop=True)

    return df


def read_csv_to_dict(file_path):
    """
    Reads a CSV file and returns a list of dictionaries where keys are the CSV
    header items.

    :param file_path: Path to the CSV file
    :return: List of dictionaries
    """
    with open(file_path, mode="r") as file:
        csv_reader = csv.DictReader(file)
        return [row for row in csv_reader]


# Start the app
st.title(TITLE)
with st.expander("About", expanded=False):
    st.markdown(ABOUT)
# Initialize current_rules as an empty DataFrame if no CSV file is uploaded


try:
    # The firewall rules sources can be a file, a hardcoded example, or modified
    # rules after applying recommendations.
    rules_file = st.sidebar.file_uploader("Upload rules file", type="csv")
    # Initialize current_rules as an empty DataFrame if no CSV file is uploaded
    if rules_file is not None:
        try:
             # Reset file pointer to handle multiple reads
            # Read file content first to check emptiness
            rules_file.seek(0)
            content = rules_file.read().strip()
            if not content:
                raise ValueError("Uploaded file is empty")
            
            # Reset and read CSV
            rules_file.seek(0)
            csv_rules = pd.read_csv(rules_file)
            
            # Validate required columns
            required_columns = ["protocol", "src", "s_port", "dst", "d_port", "action"]
            if not all(col in csv_rules.columns for col in required_columns):
                missing = [col for col in required_columns if col not in csv_rules.columns]
                raise ValueError(f"Missing columns: {', '.join(missing)}")
                
            csv_rules = csv_rules.to_dict('records')
            # Combine with manual rules
            all_rules = csv_rules + st.session_state.get("manual_rules", [])
            current_rules = pd.DataFrame(all_rules)
            
        except pd.errors.EmptyDataError:
            st.warning("The uploaded file is empty. Please upload a valid CSV file.")
            current_rules = pd.DataFrame(st.session_state.get("manual_rules", []))
        except pd.errors.ParserError as e:
            st.error(f"CSV parsing error: {str(e)}. Check file format.")
            current_rules = pd.DataFrame(st.session_state.get("manual_rules", []))
        except Exception as e:
            st.error(f"Error reading the file: {str(e)}")
            current_rules = pd.DataFrame(st.session_state.get("manual_rules", []))
    else:
            # Use only manual rules if no CSV is uploaded
        current_rules = pd.DataFrame(st.session_state.get("manual_rules", []))
                
    if "manual_rules" in st.session_state:
        manual_rules_df = pd.DataFrame(st.session_state.manual_rules)
        current_rules = pd.concat([current_rules, manual_rules_df], ignore_index=True)
    # upload test packets

    o1, o2 = st.columns(2)
    with o1:
        # The checkbox is enabled when no file is uploaded
        show_ex = rules_file is not None
        use_example = st.checkbox(
            "Use example file", value=False, disabled=show_ex, help=EXAMPLE_HELP
        )
        if use_example:
            rules_file = StringIO(EXAMPE_RULES)
    with o2:
        # The checkbox is enabled after rules are edited
        show_ed = "edited" not in st.session_state
        use_edited = st.checkbox("Use edited rules", value=False, disabled=show_ed)
        if use_edited:
            edited_file = st.session_state["edited"]
            rules_file = StringIO(edited_file)

    # If a set of rules is available as a csv file
    if rules_file is not None:
        
        if st.session_state.get('optimized', False) and 'optimized_rules' in st.session_state:
            policies = [Policy(**r) for r in st.session_state.optimized_rules]
            analyzer = PolicyAnalyzer(policies)
            anom = analyzer.get_anomalies()
            anom_dict = to_dict(anom)
            current_rules = pd.DataFrame(st.session_state.optimized_rules)
        else:
        # Use original rules
            policies = [Policy(**r) for r in current_rules.to_dict('records')]
            analyzer = PolicyAnalyzer(policies)
            anom = analyzer.get_anomalies()
            anom_dict = to_dict(anom)


        # First instance of selectboxes (under "Rules" expander)
        with st.expander("Rules"):
            st.dataframe(current_rules)
            
            # Move rows, if required
            f1, f2, f3 = st.columns(3)
            from_idx = f1.selectbox(
                "Select row index to move", 
                options=range(len(current_rules)),
                key="move_from1"  # Unique key
            )
            position = f2.selectbox(
                "Move row", 
                options=["before", "after"], 
                key="position1"  # Unique key
            )
            to_idx = f3.selectbox(
                "Select destination row index", 
                options=range(len(current_rules)), 
                key="move_to1"  # Unique key
            )

        # Later in the code (uploaded file processing section)
        f1, f2, f3 = st.columns(3)
        from_idx = f1.selectbox(
            "Select row index to move", 
            options=range(len(current_rules)), 
            key="move_from2"  # Unique key
        )
        position = f2.selectbox(
            "Move row", 
            options=["before", "after"], 
            key="position2"  # Unique key
        )
        to_idx = f3.selectbox(
            "Select destination row index", 
            options=range(len(current_rules)), 
            key="move_to2"  # Unique key
        )

            # Button to apply the move operation
            # If the rules were edited, enable download
        if use_edited:
            csv = convert_df(current_rules)
            st.download_button(
                label="Download rules",
                data=csv,
                file_name="new_rules.csv",
                mime="text/csv",
            )

        # Convert the DataFrame to a list of dictionaries with all values as strings
        rules = [{key: str(value) for key, value in row.items()}for row in current_rules.to_dict(orient="records")]
        policies = [Policy(**r) for r in rules]
        analyzer = PolicyAnalyzer(policies)
        # Find relations among firewall rules
        anom = analyzer.get_anomalies()
        anom_dict = to_dict(anom)
        st.header("Real-time Packet Testing")
        with st.form(key='real_time_test'):
            st.write("Enter packet details to test against rules:")
            col1, col2 = st.columns(2)
        with col1:
            protocol = st.selectbox("Protocol", ["tcp", "udp", "icmp", "any"])
            src = st.text_input("Source IP", value="0.0.0.0/0")
            s_port = st.text_input("Source Port", value="any")
        with col2:
            dst = st.text_input("Destination IP", value="0.0.0.0/0")
            d_port = st.text_input("Destination Port", value="any")
            test_button = st.form_submit_button("Test Packet")

        if st.button("Auto Optimize Rules"):

            if st.session_state.ml_mode:
                 # AI-Driven optimization with explanations
                expert = FirewallExpertSystem()
                policies = [Policy(**r) for r in current_rules.to_dict('records')]
                analyzer = PolicyAnalyzer(policies)
                anom = analyzer.get_anomalies()
                anom_dict = to_dict(anom)  # Use the current state of rules
                optimized_df, changes = expert.analyze_rules(current_rules, anom_dict)
                
                # Store explanations with full details
                explanations = []
                for change in changes:
                    parts = change.split()
                    anomaly_type = change.split()[1]  # Extract anomaly type
                    # Extract rule numbers using regex to handle variable formats
                    import re
                    rule_nums = re.findall(r'\d+', change)  # Find all numbers in the change string
                    if len(rule_nums) >= 2:
                        x_rule = int(rule_nums[0])
                        y_rule = int(rule_nums[1])
                    elif len(rule_nums) == 1:
                        # Handle cases where only one rule is involved (e.g., redundancy removal)
                        x_rule = int(rule_nums[0])
                        y_rule = x_rule  # Or set to -1 if not applicable
                    else:
                        continue
                    explanation = {
                        'type': anomaly_type,
                        'rules': (x_rule, y_rule),
                        'description': expert._get_explanation_text(anomaly_type, x_rule, y_rule)
                    }
                    explanations.append(explanation)

                # Update session state
                st.session_state['original_rules'] = current_rules.copy()
                st.session_state['optimization_explanations'] = explanations
                st.session_state['optimized_rules'] = optimized_df.to_dict('records')
                st.session_state.optimized = True
                st.experimental_rerun()
            # Convert anomalies to proper dict format first
            else:
                st.session_state['original_rules'] = current_rules.copy()

                original_anom = to_dict(analyzer.get_anomalies())  # Convert to correct format
                original_count = sum(len(v) for v in original_anom.values())
        
                # Generate optimized rules using converted anomalies
                optimized_df = auto_optimize_rules(current_rules, original_anom)

                st.session_state['optimization_changes'] = change_log
                # Force use of optimized rules immediately
                csv = convert_df(optimized_df)
                st.session_state['edited'] = csv.decode("utf-8")

                # Store optimized rules and mark as optimized
                st.session_state['optimized_rules'] = optimized_df.to_dict('records')
                st.session_state.optimized = True

                # Show status and refresh
                st.success(f"Optimized {len(current_rules) - len(optimized_df)} rules")
                st.experimental_rerun()

        # Then modify the rules loading section:
        if use_edited and 'optimized_rules' in st.session_state:
            policies = [Policy(**r) for r in st.session_state.optimized_rules]
            analyzer = PolicyAnalyzer(policies)
            anom = analyzer.get_anomalies()
            anom_dict = to_dict(anom)
        else: 
            policies = [Policy(**r) for r in rules]
            analyzer = PolicyAnalyzer(policies)
            anom = analyzer.get_anomalies()
            anom_dict = to_dict(anom)
            
        analyzer = PolicyAnalyzer(policies)  # This now uses either original or optimized rules

        # Add status indicator in the sidebar
        st.sidebar.markdown("---")
        if st.session_state.optimized:
            st.sidebar.success("✓ Rules optimized")
        else:
            st.sidebar.info("ⓘ Original rules loaded")

        # Existing Test Packets Section

        if test_button:
            try:
                # Create packet from inputs
                packet = Packet(
                    protocol=protocol,
                    src=src,
                    s_port=s_port,
                    dst=dst,
                    d_port=d_port
                )
                # Get matching rule
                result = analyzer.get_first_match(packet)
                
                if result:
                    rule_num, rule = result
                    st.success(f"**Match Found:** Rule {rule_num} - Action: {rule.action}")
                else:
                    st.info("**No matching rule found** - Default action is deny")
            except Exception as e:
                st.error(f"Error processing packet: {str(e)}")
        # Reformat the relations as a pandas dataframe
        relations = {}
        for y_rule, y_dict in anom_dict.items():
            col = [None] * len(rules)
            for x_rule in y_dict:
                col[x_rule] = y_dict[x_rule]
            relations[y_rule] = col

        pdr = (
            pd.DataFrame.from_dict(relations)
            .transpose()
            .dropna(axis=1, how="all")
            .fillna("")
        )
        

        st.dataframe(pdr.style.applymap(color_erros).set_table_styles([{
        'selector': 'thead',
        'props': [('background-color', '#f63366'), ('color', 'white')]}], overwrite=False).highlight_null('white'),height=400)
        # Summary Section

        if st.session_state.get('optimization_explanations'):
            st.write("**Optimization Explanations:**")
            for explanation in st.session_state['optimization_explanations']:
                with st.expander(f"{explanation['type']} between rules {explanation['rules'][0]} and {explanation['rules'][1]}"):
                    st.markdown(f"**Action Taken:** {explanation['description']}")
                    st.markdown(f"**Rule {explanation['rules'][0]}:**")
                    st.dataframe(current_rules.iloc[[explanation['rules'][0]]])
                    st.markdown(f"**Rule {explanation['rules'][1]}:**")
                    st.dataframe(current_rules.iloc[[explanation['rules'][1]]])

        # Add anomaly refresh
        if st.session_state.optimized:
            st.write("Updated relationships after optimization:")
            # Recalculate anomalies for optimized rules
            optimized_policies = [Policy(**r) for r in st.session_state.optimized_rules]

        st.header("Summary")
        if not pdr.empty:
            st.write("Relationship count:")

            # Calculate counts for each anomaly type
            count = {k: pdr[pdr == k].count().sum() for k in desc}
            c1, c2, c3, c4, c5 = st.columns(5)
            with c1:
                st.metric("SHD", count["SHD"], help=desc["SHD"]["short"])
            with c2:
                st.metric("RXD", count["RXD"], help=desc["RXD"]["short"])
            with c3:
                st.metric("RYD", count["RYD"], help=desc["RYD"]["short"])
            with c4:
                st.metric("COR", count["COR"], help=desc["COR"]["short"])
            with c5:
                st.metric("GEN", count["GEN"], help=desc["GEN"]["short"])

            # Add checkbox to hide GEN
            hide_gen = st.checkbox("Ignore Generalizations", value=False)
            if hide_gen:
                pdr = pdr.applymap(lambda x: x.replace("GEN", ""))

        else:
            st.markdown(NO_RELATION)

        # Analysis Section

        # If relations are detected
        st.header("Analysis")
        if len(anom_dict) > 0:
            st.write(SELECT_RULES)
            col1, col2 = st.columns(2)
            with col1:
                # Select one of the Y rules
                y_rule = st.selectbox("Select Y Rule:", list(anom_dict.keys()))

            with col2:
                # Get a list of related rules.
                x_list = list(anom_dict[y_rule].keys())

                # Select one of the X rules
                x_rule = st.selectbox("Select X Rule", x_list)

            if y_rule:  # note that 0 === False
                # Display the pair of selected rules
                st.dataframe(current_rules.iloc[[x_rule, y_rule]].rename(index={x_rule: f"X ({x_rule})", y_rule: f"Y ({y_rule})"}))

                # Display the discription of relations and recommendations
                acode = anom_dict[y_rule][x_rule]
                xy_rel = desc[acode]["long"]
                xy_short = desc[acode]["short"]
                xy_def = desc[acode]["def"]
                xy_desc = f"Rule **Y** ({y_rule}) {xy_rel} rule **X** ({x_rule})."
                xy_recom = desc[acode]["rec"]

                st.markdown(f"#### {xy_short}")
                st.markdown(xy_desc)
                with st.expander("Definition", expanded=False):
                    st.markdown(xy_def)
                st.markdown("#### Recommendation")
                st.markdown(xy_recom)

            # Editing Section

            if acode in errors or acode in warn:
                # Offer to apply recommendation to correct errors
                placeholder = st.empty()
                apply = placeholder.button(
                    "Apply Recommendation", disabled=False, key=1
                )

                if apply:
                    # Remove the button
                    placeholder.empty()
                    if not use_edited:
                        placeholder.markdown(
                            "Check 'Use Edited Rules' box above, to update the rules."
                        )

                    # Get pandas dataframe as a list
                    rules_list = current_rules.values.tolist()

                    if acode == "SHD" and apply:
                        # Move rule Y before rule X
                        rules_list.insert(x_rule, rules_list[y_rule])
                        del rules_list[y_rule + 1]

                    if acode == "RXD" and apply:
                        del rules_list[x_rule]

                    if acode == "RYD" and apply:
                        del rules_list[y_rule]

                    if acode == "COR" and apply:
                        # Switch rule X and rule Y places
                        rules_list[x_rule], rules_list[y_rule] = (
                            rules_list[y_rule],
                            rules_list[x_rule],
                        )

                    # Generate a CSV from the modified rules
                    newdf = pd.DataFrame(rules_list, columns=current_rules.columns)
                    csv = convert_df(newdf)

                    # Save the CSV in the session state
                    st.session_state["edited"] = csv.decode("utf-8")
                    st.session_state["optimized_rules"] = newdf.to_dict('records')  # Add this line
                    st.session_state.optimized

                    # Run the app from the top
                    st.experimental_rerun()

        else:
            st.markdown(NO_RELATION)

        st.subheader("Optimization Preview")
        if 'original_rules' in st.session_state:
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Original Rules**")
                st.dataframe(st.session_state['original_rules'])
            with col2:
                st.write("**Optimized Rules**")
                st.dataframe(current_rules)

        if st.session_state.get('optimization_changes'):
            st.write("**Changes Made:**")
            for change in st.session_state['optimization_changes']:
                st.write(f"- {change}")
        
        # Around line 672 (original error location)
        st.dataframe(
            pdr.style.applymap(color_erros).set_table_styles([{
                'selector': 'thead',
                'props': [('background-color', '#f63366'), ('color', 'white')]
            }], overwrite=False).highlight_null('white'),
            height=400
)

        # Add anomaly refresh
        if st.session_state.optimized:
            st.write("Updated relationships after optimization:")
            # Recalculate anomalies for optimized rules
            optimized_policies = [Policy(**r) for r in st.session_state.optimized_rules]
            optimized_analyzer = PolicyAnalyzer(optimized_policies)
            optimized_anom = optimized_analyzer.get_anomalies()
            anom_dict = to_dict(optimized_anom)

    else:
        st.session_state.pop("packets", None)
        st.warning(UPLOAD_FILE)
except Exception as e:
    # st.error(e)
    st.exception(e)