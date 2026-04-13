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
    st.write("This tab queries Shodan to find individual, specific IP addresses located in Iran that are currently responding to external internet traffic. During a total shutdown, this reveals the exact whitelisted infrastructure.")
    
    if not shodan_api_key:
        st.warning("⚠️ Please enter your Shodan API Key in the sidebar to load this data.")
    else:
        @st.cache_data(ttl=3600) # Cache for 1 hour to save Shodan API credits
        def fetch_shodan_ips(api_key):
            try:
                url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=country:IR&limit=100"
                res = requests.get(url, timeout=15).json()
                
                hosts = []
                for match in res.get('matches', []):
                    hosts.append({
                        "IP Address": match.get('ip_str'),
                        "ISP / Organization": match.get('org', 'Unknown'),
                        "Open Port": match.get('port'),
                        "Transport": match.get('transport', 'tcp'),
                        "Last Seen": match.get('timestamp')
                    })
                return pd.DataFrame(hosts)
            except Exception as e:
                st.error(f"Shodan API Error: {e}")
                return pd.DataFrame()

        with st.spinner("Scanning Shodan for active IR infrastructure..."):
            df_shodan = fetch_shodan_ips(shodan_api_key)
            
        if not df_shodan.empty:
            st.success(f"Successfully retrieved a sample of {len(df_shodan)} exposed IPs.")
            st.dataframe(df_shodan, use_container_width=True, hide_index=True)
            
            # Show a breakdown of which ISPs these open IPs belong to
            st.subheader("Exposed IPs by ISP")
            isp_counts = df_shodan['ISP / Organization'].value_counts()
            st.bar_chart(isp_counts)


# ==========================================
# TAB 3: DESTINATIONS (Traffic flow via OONI)
# ==========================================
with tab3:
    st.subheader("🎯 Outbound Traffic Measurements (OONI)")
    st.write("This tab pulls live probe data from volunteers inside Iran attempting to connect to external websites and services.")
    
    @st.cache_data(ttl=600) 
    def fetch_ooni_data():
        try:
            url = "https://api.ooni.io/api/v1/measurements?probe_cc=IR&test_name=web_connectivity&limit=100"
            
            # 1. Add a User-Agent header to bypass basic bot protection
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
            
            res = requests.get(url, headers=headers, timeout=15)
            
            # 2. Check if the response is actually 200 OK before parsing JSON
            if res.status_code != 200:
                st.error(f"OONI API returned a non-200 status code: {res.status_code}")
                # Print a small snippet of the text to help debug if it fails again
                st.code(res.text[:200]) 
                return pd.DataFrame()

            data = res.json()
            
            measurements = []
            for item in data.get('results', []):
                status = "✅ Accessible"
                if item.get('anomaly'):
                    status = "⚠️ Anomalous / Throttled"
                if item.get('confirmed'):
                    status = "🚨 Confirmed Blocked"
                    
                measurements.append({
                    "Timestamp (UTC)": item.get('measurement_start_time'),
                    "Target Destination": item.get('input'),
                    "Internal Network (ASN)": item.get('probe_asn'),
                    "Status": status
                })
            return pd.DataFrame(measurements)
            
        except ValueError:
             st.error("OONI API Error: Received invalid JSON. The API might be undergoing maintenance.")
             return pd.DataFrame()
        except Exception as e:
            st.error(f"OONI Request Failed: {e}")
            return pd.DataFrame()

    with st.spinner("Fetching live traffic measurements from OONI..."):
        df_ooni = fetch_ooni_data()
        
    if not df_ooni.empty:
        col_a, col_b = st.columns(2)
        with col_a:
            filter_status = st.multiselect("Filter by Status:", df_ooni['Status'].unique(), default=df_ooni['Status'].unique())
        with col_b:
            filter_asn = st.multiselect("Filter by Origin ASN:", df_ooni['Internal Network (ASN)'].unique(), default=df_ooni['Internal Network (ASN)'].unique())
            
        filtered_df = df_ooni[(df_ooni['Status'].isin(filter_status)) & (df_ooni['Internal Network (ASN)'].isin(filter_asn))]
        st.dataframe(filtered_df, use_container_width=True, hide_index=True)
