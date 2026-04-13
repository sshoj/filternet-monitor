import streamlit as st
import requests
import pandas as pd
import time
import ipaddress

st.set_page_config(page_title="Filternet Intelligence", layout="wide")

st.title("📡 Iran Filternet Intelligence Dashboard")
st.markdown("Monitoring BGP Routing, Active Exposed IPs, and Live Traffic Anomalies.")

# --- SIDEBAR FOR API KEYS ---
with st.sidebar:
    st.header("⚙️ Configuration")
    shodan_api_key = st.text_input("Shodan API Key (For Tab 2)", type="password")
    st.markdown("---")
    st.markdown("**Data Sources:**\n* RIPEstat (BGP)\n* Shodan.io (Active IPs)\n* OONI.io (Traffic Measurements)")

# Create Tabs
tab1, tab2, tab3 = st.tabs(["🌐 BGP Monitor (Macro)", "🚗 Active IPs (Shodan)", "🎯 Destinations (OONI)"])

# ==========================================
# TAB 1: BGP ROUTE MONITOR
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
                    time.sleep(0.2)
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
# TAB 2: ACTIVE IPs (Shodan)
# ==========================================
with tab2:
    st.subheader("🔍 Active Iranian IPs Exposed to the Global Internet")
    
    if not shodan_api_key:
        st.warning("⚠️ Please enter your Shodan API Key in the sidebar to load this data.")
    else:
        @st.cache_data(ttl=3600) 
        def fetch_shodan_ips(api_key):
            try:
                # Using 'Iran' instead of 'country:IR' to bypass the free-tier restriction
                url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=Iran&limit=100"
                res = requests.get(url, timeout=15)
                data = res.json()
                
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

# ==========================================
# TAB 3: DESTINATIONS & CIDR TRACKING (OONI)
# ==========================================
with tab3:
    st.subheader("🎯 Outbound Traffic & Cloud IP Tracker (OONI)")
    
    @st.cache_data(ttl=86400) 
    def get_cloudflare_ranges():
        try:
            res = requests.get("https://www.cloudflare.com/ips-v4", timeout=5)
            if res.status_code == 200:
                return res.text.strip().split('\n')
        except:
            pass
        return ["104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "103.21.244.0/22"]

    tracking_mode = st.radio("Select Tracking Mode:", ["Domain Name", "Cloud IP Range (CIDR)"], horizontal=True)

    if tracking_mode == "Domain Name":
        target_input = st.selectbox(
            "Select Target Domain:",
            ["All Recent Traffic", "microsoft.com", "aws.amazon.com", "azure.com", "github.com", "cloudflare.com"]
        )
    else:
        cf_ips = get_cloudflare_ranges()
        ip_options = ["Custom Input (Type your own)"] + [f"{ip} (Cloudflare)" for ip in cf_ips]
        selected_ip_mode = st.selectbox("Select a Live Cloudflare Range, or type a custom CIDR:", ip_options)
        
        if selected_ip_mode == "Custom Input (Type your own)":
            target_input = st.text_input("Enter custom IP or CIDR Range (e.g., 3.120.0.0/14 for AWS):", "3.120.0.0/14")
        else:
            target_input = selected_ip_mode.split(" ")[0]

    @st.cache_data(ttl=600) 
    def fetch_ooni_data(mode, target):
        try:
            test_type = "tcp_connect" if mode == "Cloud IP Range (CIDR)" else "web_connectivity"
            
            # DIRECT CALL for AWS - No Proxy Wrapper
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
            
            target_network = None
            if mode == "Cloud IP Range (CIDR)":
                try:
                    target_network = ipaddress.ip_network(target.strip(), strict=False)
                except ValueError:
                    st.error("Invalid CIDR format.")
                    return pd.DataFrame()

            for item in data.get('results', []):
                raw_input = item.get('input', '')
                clean_input = raw_input.replace('https://', '').replace('http://', '').split(':')[0]
                
                if mode == "Cloud IP Range (CIDR)":
                    try:
                        ip_obj = ipaddress.ip_address(clean_input)
                        if ip_obj not in target_network:
                            continue 
                    except ValueError:
                        continue 

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
        st.info(f"No recent volunteer tests found targeting {target_input} in the last 24 hours.")
