import streamlit as st
import requests
import pandas as pd
import time

st.set_page_config(page_title="Filternet BGP Monitor", layout="wide")

st.title("📡 Iran BGP Route Monitor (Live)")
st.markdown("Monitoring announced prefixes to detect national whitelist events and internet shutdowns.")

# Define the target ASNs grouped by category
ASN_GROUPS = {
    "Gateways (TIC)": {"AS31549": "TIC Primary"},
    "Consumer & Mobile": {"AS43754": "Irancell", "AS39501": "MCI", "AS43288": "Rightel", "AS43753": "Shatel"},
    "Data Center & Gov": {"AS58224": "TIC Government", "AS43274": "ArvanCloud", "AS49100": "Afranet"}
}

# Use Streamlit cache to prevent hitting the API on every UI interaction (caches for 5 mins)
@st.cache_data(ttl=300)
def fetch_bgp_data():
    results = []
    for category, asns in ASN_GROUPS.items():
        for asn, name in asns.items():
            try:
                # RIPEstat API endpoint
                url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
                response = requests.get(url, timeout=10).json()
                
                # Count the number of IP prefixes currently announced
                prefix_count = len(response['data']['prefixes'])
                
                results.append({
                    "Category": category,
                    "ASN": asn,
                    "Provider": name,
                    "Announced Prefixes": prefix_count
                })
                # Polite sleep to respect API limits
                time.sleep(0.2)
            except Exception as e:
                st.error(f"Failed to fetch data for {asn}: {e}")
                
    return pd.DataFrame(results)

with st.spinner("Fetching live global routing data from RIPE..."):
    df = fetch_bgp_data()

# --- Dashboard UI ---
if not df.empty:
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Current BGP Announcements")
        st.dataframe(df, use_container_width=True, hide_index=True)
        
    with col2:
        st.subheader("Network Health Snapshot")
        # Check for potential shutdowns (Consumer dropping near 0)
        consumer_routes = df[df['Category'] == 'Consumer & Mobile']['Announced Prefixes'].sum()
        gov_routes = df[df['Category'] == 'Data Center & Gov']['Announced Prefixes'].sum()
        
        st.metric(label="Total Consumer Mobile/ISP Routes", value=consumer_routes)
        st.metric(label="Total Data Center/Gov Routes", value=gov_routes)
        
        if consumer_routes < 50 and gov_routes > 100:
            st.error("🚨 ALERT: Potential Strict Whitelist/Shutdown Detected. Consumer routes are suspiciously low.")
        else:
            st.success("✅ Consumer routes are currently being announced.")

    st.divider()
    st.subheader("Prefix Distribution by Provider")
    st.bar_chart(df, x="Provider", y="Announced Prefixes", color="Category")

st.caption("Data provided by the RIPE Network Coordination Centre.")
