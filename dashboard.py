import os, sys, json
import streamlit as st
import requests

sys.path.insert(0, os.path.dirname(__file__))
API_BASE = os.environ.get("AUDITOR_API", "https://auditor-bot.onrender.com")

st.set_page_config(page_title="Smart Contract Auditor", layout="wide")
st.title("Smart Contract Auditor Dashboard")

tab1, tab2, tab3, tab4 = st.tabs(["Audit", "Gas Analysis", "Auto-PoC", "Status"])

with tab1:
    st.subheader("Code Audit")
    code = st.text_area("Paste Solidity/Vyper/Move code", height=200)
    if st.button("Run Audit") and code:
        with st.spinner("Auditing..."):
            try:
                r = requests.post(f"{API_BASE}/analyze", json={"code": code[:4000], "type": "audit", "lang": "english"}, timeout=120)
                st.markdown(r.json().get("report", r.text))
            except Exception as e:
                st.error(f"Failed: {e}")

with tab2:
    st.subheader("Gas Analysis with USD Cost")
    gas_code = st.text_area("Paste code for gas analysis", height=200, key="gas")
    if st.button("Analyze Gas") and gas_code:
        with st.spinner("Analyzing..."):
            try:
                from gas_analysis import analyze_gas, estimate_gas_savings
                report = analyze_gas(gas_code[:3000])
                savings = estimate_gas_savings(gas_code[:3000])
                st.markdown(report)
                st.metric("Estimated USD Savings", f"${savings['usd_saved']:.2f}")
                st.metric("ETH Price", f"${savings['eth_price']:.0f}")
            except Exception as e:
                st.error(f"Failed: {e}")

with tab3:
    st.subheader("Auto-PoC Validation")
    poc_code = st.text_area("Paste code", height=200, key="poc")
    if st.button("Run Auto-PoC") and poc_code:
        with st.spinner("Analyzing + generating PoC..."):
            try:
                r = requests.post(f"{API_BASE}/analyze", json={"code": poc_code[:4000], "type": "autopoc", "lang": "english"}, timeout=180)
                st.markdown(r.json().get("report", r.text))
            except Exception as e:
                st.error(f"Failed: {e}")

with tab4:
    st.subheader("System Status")
    try:
        r = requests.get(f"{API_BASE}/", timeout=10)
        st.json(r.json() if r.headers.get("content-type", "").startswith("application/json") else {"status": r.status_code})
    except Exception as e:
        st.error(f"Dashboard API unreachable: {e}")

st.caption("Smart Contract Auditor - Enterprise Grade")