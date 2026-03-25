import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from utils.helpers import load_css, card_open, card_close, metric_card, footer
from utils.db import init_db, authenticate, save_history, load_history
from utils.sms_bert import bert_available, predict_sms_bert
from utils.url_xgb import xgb_available, predict_url
from utils.reporting import build_pdf

st.set_page_config(
    page_title="Hybrid Phishing Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

load_css()
init_db()

for key, default in {"logged_in": False, "role": None, "username": None}.items():
    if key not in st.session_state:
        st.session_state[key] = default


def pill(label):
    if label == "Threat Detected":
        return "<span class='pill pill-d'>Threat Detected</span>"
    elif label == "Safe":
        return "<span class='pill pill-c'>Safe</span>"
    return "<span class='pill pill-a'>No Result</span>"


def gauge(score, title, color="#22C1FF"):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score * 100,
        number={"suffix": "%"},
        title={"text": title},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": color},
            "steps": [
                {"range": [0, 49], "color": "#123A2D"},
                {"range": [49, 70], "color": "#3B2B12"},
                {"range": [70, 100], "color": "#4A1212"},
            ]
        }
    ))
    fig.update_layout(
        height=290,
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=8, r=8, t=35, b=8)
    )
    return fig


# ---------------- CUSTOM LOGIN PAGE ----------------
if not st.session_state.logged_in:
    st.markdown("""
    <div class="top-main-banner">
        <div class="top-main-title">
            <span class="shield-icon">🛡️</span>
            Hybrid ML-Based Phishing Detection System
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="welcome-top-only">WELCOME</div>
    """, unsafe_allow_html=True)

    left, center, right = st.columns([1, 1.2, 1], gap="large")

    with left:
        st.empty()

    with center:
        st.markdown("""
        <div class="login-card">
            <div class="login-card-title">🔐 Login / Register</div>
        </div>
        """, unsafe_allow_html=True)

        tab1, tab2, tab3, tab4 = st.tabs(["Login", "Sign Up", "Forgot Password", "Verify Email"])

        with tab1:
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")

            if st.button("Login", use_container_width=True, key="login_btn"):
                ok, role = authenticate(username, password)
                if ok:
                    st.session_state.logged_in = True
                    st.session_state.role = role
                    st.session_state.username = username
                    st.success("Login successful.")
                    st.rerun()
                else:
                    st.error("Invalid username or password.")

        with tab2:
            st.info("Sign Up page will work after full user-management integration.")

        with tab3:
            st.info("Forgot Password page will work after full reset-password integration.")

        with tab4:
            st.info("Verify Email page will work after email verification integration.")

    with right:
        st.empty()

    footer()
    st.stop()


# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.image("assets/logo.svg", width=108)
    st.markdown(f"### {st.session_state.username}")
    st.caption(f"Role: {st.session_state.role}")

    page = st.radio("Navigation", [
        "System Overview",
        "Dashboard",
        "SMS Detection",
        "URL Detection",
        "Hybrid Detection",
        "Detection History",
        "Download Report",
        "Admin Dashboard",
    ])

    if st.button("Logout", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.role = None
        st.session_state.username = None
        st.rerun()

history = load_history()

if page == "System Overview":
    c1, c2, c3 = st.columns(3)
    with c1:
        metric_card("SMS Dataset", "10,000", "Ready for BERT training/testing")
    with c2:
        metric_card("URL Dataset", "10,000", "Ready for XGBoost training/testing")
    with c3:
        metric_card("Deployment", "Streamlit", "Professional login-first web app")

    card_open()
    st.subheader("Training and Testing Workflow")
    st.write("Train and test both models locally in VS Code inside the `scripts/` folder.")
    st.code("python scripts/train_bert_sms.py\npython scripts/train_xgboost_url.py\npython scripts/evaluate_models.py")
    st.write("After training, the web app loads the saved models from `models/bert_sms_model/` and `models/url/`.")
    card_close()

elif page == "Dashboard":
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Total Scans", str(len(history)), "All recorded scans")
    with c2:
        metric_card("SMS Scans", str(len(history[history['input_type'] == 'SMS']) if len(history) else 0), "BERT activity")
    with c3:
        metric_card("URL Scans", str(len(history[history['input_type'] == 'URL']) if len(history) else 0), "XGBoost activity")
    with c4:
        metric_card("Threats", str(len(history[history['prediction'] == 'Threat Detected']) if len(history) else 0), "Flagged malicious content")

    if len(history) > 0:
        a, b = st.columns(2)
        with a:
            x = history["input_type"].value_counts().reset_index()
            fig = px.bar(x, x="input_type", y="count", title="Scans by Module")
            fig.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
        with b:
            y = history["prediction"].value_counts().reset_index()
            fig2 = px.pie(y, names="prediction", values="count", title="Prediction Distribution")
            fig2.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig2, use_container_width=True)

elif page == "SMS Detection":
    card_open()
    st.subheader("BERT SMS Detection")
    sms_text = st.text_area("Paste suspicious SMS", height=220)
    run = st.button("Run SMS Detection", use_container_width=True)
    card_close()

    if run:
        if not bert_available():
            st.error("BERT model not found yet. Run: python scripts/train_bert_sms.py")
        elif not sms_text.strip():
            st.warning("Please enter an SMS message.")
        else:
            label, score = predict_sms_bert(sms_text)
            save_history("SMS", sms_text, label, score)
            a, b = st.columns(2)
            with a:
                card_open()
                st.subheader("Prediction")
                st.markdown(pill(label), unsafe_allow_html=True)
                st.write(f"Confidence: {score:.2%}")
                card_close()
            with b:
                card_open()
                st.plotly_chart(gauge(score, "SMS Threat Confidence"), use_container_width=True)
                card_close()

elif page == "URL Detection":
    card_open()
    st.subheader("XGBoost URL Detection")
    c1, c2, c3 = st.columns(3)
    with c1:
        url_length = st.number_input("URL length", min_value=0, value=85)
        host_length = st.number_input("Host length", min_value=0, value=26)
        path_length = st.number_input("Path length", min_value=0, value=34)
        num_dots = st.number_input("Number of dots", min_value=0, value=4)
    with c2:
        num_hyphens = st.number_input("Number of hyphens", min_value=0, value=2)
        num_at = st.number_input("Number of @ symbols", min_value=0, value=0)
        num_digits = st.number_input("Number of digits", min_value=0, value=6)
        has_https = st.selectbox("Uses HTTPS", [1, 0], index=0)
    with c3:
        entropy = st.number_input("Entropy", min_value=0.0, value=4.6, step=0.1)
        has_login_word = st.selectbox("Contains 'login'", [1, 0], index=1)
        has_verify_word = st.selectbox("Contains 'verify'", [1, 0], index=1)
    run = st.button("Run URL Detection", use_container_width=True)
    card_close()

    if run:
        if not xgb_available():
            st.error("XGBoost URL model not found yet. Run: python scripts/train_xgboost_url.py")
        else:
            features = {
                "url_length": url_length, "host_length": host_length, "path_length": path_length,
                "num_dots": num_dots, "num_hyphens": num_hyphens, "num_at": num_at,
                "num_digits": num_digits, "has_https": has_https, "entropy": entropy,
                "has_login_word": has_login_word, "has_verify_word": has_verify_word
            }
            label, score, explain = predict_url(features)
            save_history("URL", str(features), label, score)
            a, b = st.columns(2)
            with a:
                card_open()
                st.subheader("Prediction")
                st.markdown(pill(label), unsafe_allow_html=True)
                st.write(f"Confidence: {score:.2%}")
                card_close()
            with b:
                card_open()
                st.plotly_chart(gauge(score, "URL Threat Confidence", "#3B82F6"), use_container_width=True)
                card_close()

            if explain:
                card_open()
                st.subheader("Explainability")
                df = pd.DataFrame(explain)
                fig = px.bar(df, x="feature", y="importance", color="value", title="Top URL Feature Importance")
                fig.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
                st.plotly_chart(fig, use_container_width=True)
                st.dataframe(df, use_container_width=True)
                card_close()

elif page == "Hybrid Detection":
    card_open()
    st.subheader("Hybrid Detection")
    sms_text = st.text_area("SMS message (optional)", height=140)
    st.caption("Fill URL features below")
    c1, c2, c3 = st.columns(3)
    with c1:
        url_length = st.number_input("URL length", min_value=0, value=85, key="h1")
        host_length = st.number_input("Host length", min_value=0, value=26, key="h2")
        path_length = st.number_input("Path length", min_value=0, value=34, key="h3")
        num_dots = st.number_input("Number of dots", min_value=0, value=4, key="h4")
    with c2:
        num_hyphens = st.number_input("Number of hyphens", min_value=0, value=2, key="h5")
        num_at = st.number_input("Number of @ symbols", min_value=0, value=0, key="h6")
        num_digits = st.number_input("Number of digits", min_value=0, value=6, key="h7")
        has_https = st.selectbox("Uses HTTPS", [1, 0], index=0, key="h8")
    with c3:
        entropy = st.number_input("Entropy", min_value=0.0, value=4.6, step=0.1, key="h9")
        has_login_word = st.selectbox("Contains 'login'", [1, 0], index=1, key="h10")
        has_verify_word = st.selectbox("Contains 'verify'", [1, 0], index=1, key="h11")
    run = st.button("Run Hybrid Detection", use_container_width=True)
    card_close()

    if run:
        if not xgb_available():
            st.error("Train URL model first: python scripts/train_xgboost_url.py")
        else:
            sms_score, sms_label = None, "No Result"
            if sms_text.strip():
                if not bert_available():
                    st.error("Train BERT first: python scripts/train_bert_sms.py")
                    st.stop()
                sms_label, sms_score = predict_sms_bert(sms_text)

            url_features = {
                "url_length": url_length, "host_length": host_length, "path_length": path_length,
                "num_dots": num_dots, "num_hyphens": num_hyphens, "num_at": num_at,
                "num_digits": num_digits, "has_https": has_https, "entropy": entropy,
                "has_login_word": has_login_word, "has_verify_word": has_verify_word
            }
            url_label, url_score, _ = predict_url(url_features)

            scores = [x for x in [sms_score, url_score] if x is not None]
            final_score = sum(scores) / len(scores)
            final_label = "Threat Detected" if final_score >= 0.5 else "Safe"
            save_history("HYBRID", f"SMS={sms_text[:80]} | URL={url_features}", final_label, final_score)

            a, b, c = st.columns(3)
            with a:
                card_open()
                st.subheader("SMS")
                st.markdown(pill(sms_label), unsafe_allow_html=True)
                st.write(f"Score: {sms_score:.2%}" if sms_score is not None else "No SMS")
                card_close()
            with b:
                card_open()
                st.subheader("URL")
                st.markdown(pill(url_label), unsafe_allow_html=True)
                st.write(f"Score: {url_score:.2%}")
                card_close()
            with c:
                card_open()
                st.subheader("Hybrid")
                st.markdown(pill(final_label), unsafe_allow_html=True)
                st.write(f"Final: {final_score:.2%}")
                card_close()

            chart_df = pd.DataFrame({
                "module": ["SMS", "URL", "Hybrid"],
                "score": [0 if sms_score is None else sms_score * 100, url_score * 100, final_score * 100]
            })
            fig = px.bar(chart_df, x="module", y="score", title="Hybrid Confidence Comparison")
            fig.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)

elif page == "Detection History":
    card_open()
    st.subheader("Detection History")
    if len(history) > 0:
        st.dataframe(history, use_container_width=True, height=520)
    else:
        st.info("No history yet.")
    card_close()

elif page == "Download Report":
    card_open()
    st.subheader("Download Reports")
    if len(history) > 0:
        csv = history.to_csv(index=False).encode("utf-8")
        st.download_button("Download CSV Report", data=csv, file_name="phishing_detection_report.csv", mime="text/csv", use_container_width=True)
        pdf_path = build_pdf(history.head(150), "reports/phishing_detection_report.pdf")
        with open(pdf_path, "rb") as f:
            st.download_button("Download PDF Report", data=f.read(), file_name="phishing_detection_report.pdf", mime="application/pdf", use_container_width=True)
    else:
        st.info("No report available yet.")
    card_close()

elif page == "Admin Dashboard":
    if st.session_state.role != "admin":
        st.warning("Admin dashboard is best viewed with admin account.")
    if len(history) > 0:
        a, b = st.columns(2)
        with a:
            d1 = history["prediction"].value_counts().reset_index()
            fig1 = px.pie(d1, names="prediction", values="count", title="Prediction Distribution")
            fig1.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig1, use_container_width=True)
        with b:
            d2 = history["input_type"].value_counts().reset_index()
            fig2 = px.bar(d2, x="input_type", y="count", title="Activity by Module")
            fig2.update_layout(height=340, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig2, use_container_width=True)

        card_open()
        st.subheader("Recent Activity")
        st.dataframe(history.head(30), use_container_width=True, height=420)
        card_close()
    else:
        st.info("No analytics yet.")

footer()
