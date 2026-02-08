import streamlit as st
import pandas as pd
import os
from engine import process_pcap

# Set Page Configuration
st.set_page_config(page_title="Industrial Protocol Decoder", layout="wide")

st.title("🛡️ OT Network Traffic Decoder")
st.markdown("Upload a PCAP file to decode **Modbus TCP** and core networking layers.")

# 1. Create a file uploader widget with validation
uploaded_file = st.file_uploader(
    "Choose a PCAP or PCAPNG file", 
    type=['pcap', 'pcapng'], 
    help="Only standard packet capture files are supported."
)

if uploaded_file is not None:
    # 2. Save the uploaded file temporarily to disk so Scapy can read it
    temp_path = os.path.join("temp", "temp_upload.pcap")
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.success(f"File '{uploaded_file.name}' uploaded successfully!")

    # 3. Pass the file to engine.py for processing
    with st.spinner("Analyzing packets..."):
        try:
            data = process_pcap(temp_path)
            
            if data:
                # 4. Convert results to a DataFrame for clean display
                df = pd.DataFrame(data)
                
                # Reorder columns for better readability
                column_order = ["src_ip", "src_port", "dst_ip", "dst_port", "proto", "app_proto", "details"]
                df = df[column_order]

                st.subheader("Decoded Packet Data")
                st.dataframe(df, use_container_width=True)
                
                # Optional: Add basic stats
                st.sidebar.header("Traffic Summary")
                st.sidebar.write(f"Total Packets: {len(df)}")
                st.sidebar.write(f"Modbus Packets: {len(df[df['app_proto'] == 'Modbus TCP'])}")
            else:
                st.warning("No IP packets found in this capture.")
        
        except Exception as e:
            st.error(f"Error processing file: {e}")
        
        finally:
            # Clean up the temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)

else:
    st.info("Please upload a PCAP file to begin analysis.")