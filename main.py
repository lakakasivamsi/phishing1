import os
import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import base64
import pandas as pd
from datetime import datetime


# Function to extract domain from URL
def get_domain(url):
    try:
        domain = urlparse(url).netloc
        return domain
    except:
        return None

# Validate URL structure
def is_valid_url(url):
    pattern = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(pattern, url) is not None

# Load phishing dataset
@st.cache_data  # Cache the dataset for performance
def load_phishing_dataset(file_path):
    try:
        df = pd.read_csv(file_path)
        df['Domain'] = df['URL'].apply(get_domain)
        return df
    except Exception as e:
        st.error(f"Error loading dataset: {e}")
        return pd.DataFrame(columns=["URL", "Label", "Domain"])

# Simple heuristic-based phishing detection function enhanced with dataset
def detect_phishing(url, phishing_df):
    domain = get_domain(url)

    phishing_indicators = [
        re.compile(base64.b64decode('ZnJlZQ==').decode(), re.IGNORECASE),  # "free"
        re.compile(base64.b64decode('bG9naW4=').decode(), re.IGNORECASE),  # "login"
        re.compile(base64.b64decode('c2VjdXJl').decode(), re.IGNORECASE),  # "secure"
        re.compile(base64.b64decode('YWNjb3VudA==').decode(), re.IGNORECASE),  # "account"
        re.compile(base64.b64decode('dmVyaWZ5').decode(), re.IGNORECASE),  # "verify"
    ]

    if not domain:
        return "Invalid URL"

    # Check against phishing dataset
    if domain in phishing_df['Domain'].values:
        return "Phishing Website Detected (Listed in Dataset)"
    elif url in phishing_df['URL'].values:
        return "Phishing Website Detected (URL Listed in Dataset)"

    # Check if it uses HTTPS
    is_https = urlparse(url).scheme == 'https'

    # Check for suspicious keywords in domain name
    for pattern in phishing_indicators:
        if pattern.search(domain):
            return "Phishing Website Detected (Suspicious Keywords)"

    # Heuristic: Long domain names or non-HTTPS websites are suspicious
    if len(domain) > 30:
        return "Suspicious: Domain name is too long"

    if not is_https:
        return "Suspicious: URL does not use HTTPS"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.title and "phishing" in soup.title.string.lower():
                return "Phishing Website Detected (Title Indicates Phishing)"
        else:
            return "Website Unreachable"
    except requests.exceptions.RequestException:
        return "Error accessing the website"

    return "Legitimate Website"

# Color coding for results
def get_result_color(result):
    if "Phishing" in result:
        return "red"
    elif "Suspicious" in result:
        return "orange"
    elif "Legitimate" in result:
        return "green"
    else:
        return "gray"

# History to store searched URLs
search_history = []

# Streamlit App
st.set_page_config(page_title="Phishing Detector", page_icon="🔍", layout="centered")

st.title("🔍 Phishing Website Detection")
st.markdown("Enter a URL to check if it's legitimate or potentially a phishing website.")

# Load the phishing dataset
dataset_file = 'phishing_url.csv'  # Ensure this file is in the same directory or provide the correct path
phishing_df = load_phishing_dataset(dataset_file)

# Input URL
url = st.text_input("Enter Website URL", "")

# Button to detect phishing
if st.button("Check for Phishing"):
    if url:
        if is_valid_url(url):
            result = detect_phishing(url, phishing_df)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            search_history.append((timestamp, url, result))
            st.markdown(f'<p style="color:{get_result_color(result)};"><strong>Result:</strong> {result}</p>', unsafe_allow_html=True)
        else:
            st.error("Invalid URL format. Please enter a valid URL.")
    else:
        st.warning("Please enter a URL.")

# Show URL analysis
if url:
    st.subheader("URL Analysis")
    domain = get_domain(url)
    st.write(f"**Domain:** {domain}")
    st.write(f"**URL Length:** {len(url)}")
    st.write(f"**Uses HTTPS:** {'Yes' if url.startswith('https') else 'No'}")

# Button to display search history
if st.button("Show Search History"):
    if search_history:
        st.subheader("Search History")
        df_history = pd.DataFrame(search_history, columns=["Timestamp", "URL", "Result"])
        st.dataframe(df_history)
    else:
        st.write("No search history found.")

# Button to export history to CSV
if search_history:
    df_history = pd.DataFrame(search_history, columns=["Timestamp", "URL", "Result"])
    csv = df_history.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download Search History as CSV",
        data=csv,
        file_name="search_history.csv",
        mime="text/csv",
    )
    

dataset_file = r'C:\path\to\your\phishing_url.csv'  # Use raw string if needed


# Footer
st.markdown("---")
st.markdown("© vamsi. All rights reserved.")
