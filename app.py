import streamlit as st
import requests
import pandas as pd
import time

st.set_page_config(page_title="Filternet Intelligence", layout="wide")

st.title("📡 Iran Filternet Intelligence Dashboard")
st.markdown("Monitoring BGP Routing, Active Exposed IPs, and Live Traffic Anomalies.")

# --- SIDEBAR FOR API KEYS ---
with st.sidebar:
    st.header("⚙️ Configuration")
    shodan_api_key = st.text_input("Shodan API Key (For Tab 2)", type="password", help="Get a free key from account.shodan.io")
    st.markdown("---")
    st.markdown("**Data Sources:**\n* RIPEstat (BGP)\n* Shodan.io (Active IPs)\n* OONI.io (Traffic Measurements)")

# Create Tabs
tab1, tab2, tab3 = st.tabs(["🌐 BGP Monitor (Macro)", "🚗 Active IPs (Shodan)", "🎯 Destinations (OONI)"])

# ==========================================
# TAB 1: BGP ROUTE MONITOR (The Macro View)
# ==========================================
with tab1:
    ASN_GROUPS = {
        "Gateways (TIC)": {"AS31549": "TIC Primary"},
        "Consumer & Mobile": {"AS43754": "Irancell", "AS39501": "MCI", "AS43288": "Rightel", "AS43753": "Shatel"},
        "Data Center & Gov": {"AS58224": "TIC Government", "AS43274": "ArvanCloud", "AS49100": "Afranet"}
    }

    @st.cache_data(ttl=300)
    def fetch_bgp_data():
        results = []
        for category, asns in ASN_GROUPS.items():
            for asn, name in asns.items():
                try:
                    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
                    response = requests.get(url, timeout=10).json()
                    prefix_count = len(response['data']['prefixes'])
                    results.append({"Category": category, "ASN": asn, "Provider": name, "Announced Prefixes": prefix_count})
                    time.sleep(0.2) # Polite API delay
                except:
                    pass
        return pd.DataFrame(results)

    with st.spinner("Fetching BGP Data from RIPE..."):
        df_bgp = fetch_bgp_data()

    if not df_bgp.empty:
        col1, col2 = st.columns([2, 1])
        with col1:
            st.subheader("Current BGP Announcements")
            st.dataframe(df_bgp, use_container_width=True, hide_index=True)
            st.bar_chart(df_bgp, x="Provider", y="Announced Prefixes", color="Category")
        with col2:
            st.subheader("Network Health Snapshot")
            consumer_routes = df_bgp[df_bgp['Category'] == 'Consumer & Mobile']['Announced Prefixes'].sum()
            gov_routes = df_bgp[df_bgp['Category'] == 'Data Center & Gov']['Announced Prefixes'].sum()
            
            st.metric(label="Total Consumer Mobile/ISP Routes", value=consumer_routes)
            st.metric(label="Total Data Center/Gov Routes", value=gov_routes)
            
            if consumer_routes < 50 and gov_routes > 100:
                st.error("🚨 ALERT: Potential Strict Whitelist. Consumer routes are critically low.")
            else:
                st.success("✅ Consumer routes are currently being announced.")


# ==========================================
# TAB 2: ACTIVE IPs (The "Cars" via Shodan)
# ==========================================
with tab2:
    st.subheader("🔍 Active Iranian IPs Exposed to the Global Internet")
    st.write("This tab queries Shodan to find individual, specific IP addresses located in Iran that are currently responding to external internet traffic.")
    
    if not shodan_api_key:
        st.warning("⚠️ Please enter your Shodan API Key in the sidebar to load this data.")
    else:
        @st.cache_data(ttl=3600) 
        def fetch_shodan_ips(api_key):
            try:
                url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=Iran&limit=100"
                res = requests.get(url, timeout=15)
                data = res.json()
                
                # Catch specific Shodan API errors (like Invalid Key)
                if 'error' in data:
                    st.error(f"Shodan API Rejected the Request: {data['error']}")
                    return pd.DataFrame()
                
                hosts = []
                for match in data.get('matches', []):
                    hosts.append({
                        "IP Address": match.get('ip_str'),
                        "ISP / Organization": match.get('org', 'Unknown'),
                        "Open Port": match.get('port'),
                        "Transport": match.get('transport', 'tcp'),
                        "Last Seen": match.get('timestamp')
                    })
                return pd.DataFrame(hosts)
            except Exception as e:
                st.error(f"Network Error reaching Shodan: {e}")
                return pd.DataFrame()

        with st.spinner("Scanning Shodan for active IR infrastructure..."):
            df_shodan = fetch_shodan_ips(shodan_api_key)
            
        if not df_shodan.empty:
            st.success(f"Successfully retrieved a sample of {len(df_shodan)} exposed IPs.")
            st.dataframe(df_shodan, use_container_width=True, hide_index=True)
            
            st.subheader("Exposed IPs by ISP")
            isp_counts = df_shodan['ISP / Organization'].value_counts()
            st.bar_chart(isp_counts)
        elif shodan_api_key:
            st.info("No results returned. Check if the API key is correct and has available credits.")

import ipaddress # Make sure this is at the top of your file!

# ==========================================
# TAB 3: DESTINATIONS & CIDR TRACKING (OONI)
# ==========================================
with tab3:
    st.subheader("🎯 Outbound Traffic & Cloud IP Tracker (OONI)")
    st.write("Track specific domains or scan recent traffic to see if entire Cloud subnets (AWS/Azure) are being blocked.")
    
    # Let the user choose what to track
    tracking_mode = st.radio("Select Tracking Mode:", ["Domain Name", "Cloud IP Range (CIDR)"], horizontal=True)

    if tracking_mode == "Domain Name":
        target_input = st.selectbox(
            "Select Target Domain:",
            ["All Recent Traffic", "microsoft.com", "aws.amazon.com", "azure.com", "github.com", "cloudflare.com"]
        )
    else:
        # Provide a default AWS Frankfurt subnet as an example
        target_input = st.text_input("Enter IP or CIDR Range (e.g., 3.120.0.0/14 for AWS Frankfurt):", "3.120.0.0/14")

    @st.cache_data(ttl=600) 
    def fetch_ooni_data(mode, target):
        try:
            # If searching for IPs, tcp_connect is better because circumvention tools ping raw IPs
            test_type = "tcp_connect" if mode == "Cloud IP Range (CIDR)" else "web_connectivity"
            url = f"https://api.ooni.io/api/v1/measurements?probe_cc=IR&test_name={test_type}&limit=300"
            
            if mode == "Domain Name" and target != "All Recent Traffic":
                url += f"&domain={target}"

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept": "application/json"
            }
            res = requests.get(url, headers=headers, timeout=20)
            
            if res.status_code != 200:
                st.error(f"API Error: {res.status_code}")
                return pd.DataFrame()

            data = res.json()
            measurements = []
            
            # Setup CIDR checking if in IP mode
            target_network = None
            if mode == "Cloud IP Range (CIDR)":
                try:
                    target_network = ipaddress.ip_network(target.strip(), strict=False)
                except ValueError:
                    st.error("Invalid CIDR format. Please use formats like 1.1.1.1 or 18.100.0.0/16")
                    return pd.DataFrame()

            for item in data.get('results', []):
                # Clean up the input to extract just the IP or Domain
                raw_input = item.get('input', '')
                clean_input = raw_input.replace('https://', '').replace('http://', '').split(':')[0]
                
                # If we are in CIDR mode, check if the tested IP falls inside the target subnet
                if mode == "Cloud IP Range (CIDR)":
                    try:
                        ip_obj = ipaddress.ip_address(clean_input)
                        if ip_obj not in target_network:
                            continue # Skip this result, it's not in the AWS/Azure range
                    except ValueError:
                        continue # Skip if the input wasn't a valid raw IP

                status = "✅ Accessible"
                if item.get('anomaly'): status = "⚠️ Anomalous / Throttled"
                if item.get('confirmed'): status = "🚨 Confirmed Blocked"
                    
                measurements.append({
                    "Timestamp (UTC)": item.get('measurement_start_time'),
                    "Target Destination": raw_input,
                    "Internal Network (ASN)": item.get('probe_asn'),
                    "Status": status
                })
            return pd.DataFrame(measurements)
            
        except Exception as e:
            st.error(f"Request Failed: {e}")
            return pd.DataFrame()

    with st.spinner(f"Analyzing network data for {target_input}..."):
        df_ooni = fetch_ooni_data(tracking_mode, target_input)
        
    if not df_ooni.empty:
        st.success(f"Found {len(df_ooni)} recent tests matching your criteria.")
        col_a, col_b = st.columns(2)
        with col_a:
            filter_status = st.multiselect("Filter by Status:", df_ooni['Status'].unique(), default=df_ooni['Status'].unique())
        with col_b:
            filter_asn = st.multiselect("Filter by Origin ASN:", df_ooni['Internal Network (ASN)'].unique(), default=df_ooni['Internal Network (ASN)'].unique())
            
        filtered_df = df_ooni[(df_ooni['Status'].isin(filter_status)) & (df_ooni['Internal Network (ASN)'].isin(filter_asn))]
        st.dataframe(filtered_df, use_container_width=True, hide_index=True)
    else:
        if tracking_mode == "Cloud IP Range (CIDR)":
            st.info(f"No recent volunteer tests found targeting the specific subnet {target_input} in the last 24 hours. (This is common for highly specific IP ranges).")
        else:
            st.info(f"No data found for {target_input}.")
