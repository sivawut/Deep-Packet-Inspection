import streamlit as st
import mysql.connector
import pandas as pd

# Database connection
def get_connection():
    return mysql.connector.connect(
        host="localhost",       # change to your DB host
        user="pipe",       # change to your DB user
        password="password",   # change to your DB password
        database="capstone"      # change to your DB name
    )

# Query to fetch data
def fetch_data():
    query = """
    SELECT status, host, method, parameter, user_agent, timestamp, response 
    FROM http 
    ORDER BY timestamp DESC
    """
    conn = get_connection()
    df = pd.read_sql(query, conn)
    conn.close()
    return df

def get_blocked_count():
    query = "SELECT COUNT(status) as blocked_count FROM http WHERE status = 'block'"
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else 0   

def get_allowed_count():
    query = "SELECT COUNT(status) as allowed_count FROM http WHERE status = 'allow'"
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else 0    



# Streamlit UI
st.title("HTTP Traffic Dashboard")

# Streamlit UI
st.subheader("Traffic Summary")
blocked_count = get_blocked_count()

#st.metric(label="Blocked Request", value=blocked_count)

allowed_count = get_allowed_count()


# Streamlit UI

col1, col2 = st.columns(2)

with col1:
    st.markdown(f"""
        <div style="background-color:#ffe6e6;padding:20px;border-radius:10px">
            <h3 style="color:red;">🚫 Blocked Requests</h3>
            <p style="font-size:30px;font-weight:bold;">{blocked_count}</p>
        </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
        <div style="background-color:#e8f5e9;padding:20px;border-radius:10px">
            <h3 style="color:green">✅ Allowed Requests</h3>
            <p style="font-size:30px;font-weight:bold;">{allowed_count}</p>
        </div>
    """, unsafe_allow_html=True)  


# Streamlit UI
st.subheader("HTTP Request Log")
try:
    data = fetch_data()
    st.dataframe(data)
except Exception as e:
    st.error(f"Error fetching data: {e}")
