import streamlit as st
import pandas as pd
import altair as alt
import requests
import os

st.set_page_config(page_title="SecureFlow Dashboard", layout="wide")
API_URL = os.environ.get("API_URL", "http://127.0.0.1:8000")

st.title("🛡️ SecureFlow DevSecOps Dashboard")

if st.button("🚀 Run New Scan"):
    with st.spinner("Scanning Repository and Cloud Environments..."):
        try:
            resp = requests.post(f"{API_URL}/scan?target_path=./sample_repo")
            st.session_state['scan_data'] = resp.json()
            st.success("Scan Complete!")
        except Exception as e:
            st.error(f"Failed to connect to API: {e}")

if 'scan_data' in st.session_state:
    data = st.session_state['scan_data']
    tm = data.get("threat_model", {})
    
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "SAST Results", "IaC & Cloud", "Threat Model"])
    
    with tab1:
        st.header("Executive Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Findings", len(data['sast_findings']) + len(data['iac_findings']))
        col2.metric("Critical Risks Count", len(tm.get("top_critical", [])))
        score = tm.get('total_risk_score', 0)
        color = "🟢" if score < 4 else "🟡" if score < 7 else "🔴"
        col3.metric("Overall Risk Score", f"{color} {score:.1f} / 10.0")
        
    with tab2:
        st.header("Code Vulnerabilities (SAST)")
        if data['sast_findings']:
            df_sast = pd.DataFrame(data['sast_findings'])
            st.dataframe(df_sast[['file', 'line', 'severity', 'issue_text', 'cwe_id']], use_container_width=True)
        else:
            st.info("No SAST findings detected.")
            
    with tab3:
        st.header("Infrastructure & Cloud Misconfigurations")
        st.subheader("Infrastructure as Code")
        if data['iac_findings']:
            st.dataframe(pd.DataFrame(data['iac_findings']), use_container_width=True)
            
        st.subheader("Cloud Environment Audits")
        if data['cloud_findings']:
            st.dataframe(pd.DataFrame(data['cloud_findings']), use_container_width=True)
            
    with tab4:
        st.header("STRIDE Threat Model & Mitigations")
        colA, colB = st.columns([2, 1])
        
        with colA:
            stride_data = tm.get("findings_by_stride", {})
            df_stride = pd.DataFrame(list(stride_data.items()), columns=['Category', 'Count'])
            chart = alt.Chart(df_stride).mark_bar().encode(
                x='Count:Q',
                y=alt.Y('Category:N', sort='-x'),
                color='Category:N'
            ).properties(height=300)
            st.altair_chart(chart, use_container_width=True)
            
        with colB:
            st.subheader("Top Critical Risks")
            for r in tm.get("top_critical", []):
                st.warning(f"**{r['category']}** (Score: {r['score']})\n\n{r['issue'][:60]}...")
                
        st.subheader("Recommended Mitigations")
        for cat, recs in tm.get("mitigations", {}).items():
            if stride_data.get(cat, 0) > 0:
                with st.expander(f"Mitigations for {cat}"):
                    for rec in recs: st.write(f"- {rec}")