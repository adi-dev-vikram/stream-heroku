import streamlit as st
import pandas as pd
import csv
import base64
import pandas as pd
from prettytable import PrettyTable
import numpy as np
from scapy.all import *
import matplotlib.pyplot as plt
from collections import Counter
from scapy.layers.dns import DNS, DNSQR

st.title('PCAP File Analyser')

st.markdown("""
This app performs simple pcap analysis and provides insights about traffic data along with downloadable reports which saves time !!
""")

st.header('Display essentials statistics derived from PCAP file')


def domain_search(result, pcap_file):
  domain = result

  for packet in pcap_file:
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname
        st.write("here")
        if domain in query:
          st.write(query + '\n')
        else:
          st.write("Domain not found")


# Download stats
def textfiledownload(raw_text):
    b64 = base64.b64encode(raw_text.encode()).decode()  # strings <-> bytes conversions
    new_filename = "dns_ip_report.txt"
    st.markdown("#### Download File ###")
    href = f'<a href="data:file/txt;base64,{b64}" download="{new_filename}">Download Report File</a>'
    st.markdown(href, unsafe_allow_html=True)
    return href


PIE_PLOT_DATA = []

def read_pcap(packets_list):
  count_UDP = count_TCP = 0
  
  dns_ip_list =[]
  for pkt in packets_list:
    if pkt.haslayer(DNSQR):
      query = pkt[DNSQR].qname
    i = 0
    for i in range(0,50):
      if pkt.haslayer(IP):
        pckt_src=pkt[IP].src
        pckt_dst=pkt[IP].dst
        pckt_ttl=pkt[IP].ttl
        dns_ip_list += [str("IP Packet: {} is going to {} and has ttl value {}".format(pckt_src,pckt_dst,pckt_ttl))]
    if pkt.haslayer(IP):
      if pkt[IP].proto == 17:
        count_UDP += 1
      if pkt[IP].proto ==6:
        count_TCP += 1
  
  with open('shows_details.csv','w') as file:
    for line in dns_ip_list:
        file.write(line)
        file.write('\n')
  data = pd.read_csv("shows.csv") #path folder of the data file
  st.markdown("### Src IP and ttl details###")
  st.write(data)
  textfiledownload(" ".join(dns_ip_list))

  PIE_PLOT_DATA.append(count_UDP)
  PIE_PLOT_DATA.append(count_TCP)
  piePlot()

def piePlot():
  DATA_TYPE = ['UDP','TCP']
  explode = (0.1, 0.0)
 
  # Creating color parameters
  colors = ( "indigo", "beige")
 
  # Wedge properties
  wp = { 'linewidth' : 1, 'edgecolor' : "black" }
 
  # Creating autocpt arguments
  def func(pct, allvalues):
    absolute = int(pct / 100.*np.sum(allvalues))
    return "{:.1f}%\n({:d} g)".format(pct, absolute)
 
  # Creating plot
  fig, ax = plt.subplots(figsize =(10, 7))
  wedges, texts, autotexts = ax.pie(PIE_PLOT_DATA,
                                  autopct = lambda pct: func(pct, PIE_PLOT_DATA),
                                  explode = explode,
                                  labels = DATA_TYPE,
                                  shadow = True,
                                  colors = colors,
                                  startangle = 90,
                                  wedgeprops = wp,
                                  textprops = dict(color ="magenta"))
 
  # Adding legend
  ax.legend(wedges, DATA_TYPE,
          title ="Data Types",
          loc ="center left",
          bbox_to_anchor =(1, 0, 0.5, 1))
 
  plt.setp(autotexts, size = 8, weight ="bold")
  ax.set_title("Customizing pie chart")
 
  # show plot
  plt.show()
  st.balloons()
  st.pyplot(fig)

def process_src_IP(packets):
  srcIP=[]
  for pkt in packets:
    if IP in pkt:
      try:
        srcIP.append(pkt[IP].src)
      except:
        pass
  
  cnt=Counter()
  for ip in srcIP:
    cnt[ip] += 1
  xData=[]
  yData=[]
  for ip, count in cnt.most_common():
    xData.append(ip)
    yData.append(count)

  table= PrettyTable(["IP", "Count"])
  for ip, count in cnt.most_common():
    table.add_row([ip, count])

  fig = plt.figure(figsize = (10, 5))
  plt.bar(xData,yData)
  plt.title("Src IP count")
  plt.xlabel("Src IPs ")
  plt.ylabel("Number of times it occuered ")
  plt.xticks(xData, rotation='vertical')
  plt.show()
  
  result = []
  st.pyplot(fig)

  # for line in table.splitlines():
  #     splitdata = line.split("|")
  #     if len(splitdata) == 1:
  #         continue  # skip lines with no separators
  #     linedata = []
  #     for field in splitdata:
  #         field = field.strip()
  #         if field:
  #             linedata.append(field)
  #     result.append(linedata)

  #     with open('pcapstats.csv', 'wb') as outcsv:
  #       writer = csv.writer(outcsv)
  #       writer.writerows(result)

  #st.markdown(filedownload(writer), unsafe_allow_html=True) 

def main():
  st.sidebar.title("File Type")
  file_type = st.sidebar.selectbox('To Upload', ['Dataset', 'Packet capture'], key='1')
  ml_algo_type = st.sidebar.selectbox('Machine Learning Algorithms', ['kNN', 'Random Forest', 'SVM'], key='1')

  if file_type == "Dataset":
    st.subheader("Dataset")
    data_file = st.file_uploader("Upload CSV",type=['csv'])
    if st.button("Process"):
      if data_file is not None:
        file_details = {"Filename":data_file.name,"FileType":data_file.type,"FileSize":data_file.size}
        st.write(file_details)
        df = pd.read_csv(data_file)
        st.dataframe(df)
  elif file_type == "Packet capture":
    st.subheader("Packet capture")
    pcap_file = st.file_uploader("Upload PCAP",type=None)
    if st.button("Process"):
      if pcap_file is not None:
        st.markdown("### File Details ###")
        file_details = {"Filename":pcap_file.name,"FileType":pcap_file.type,"FileSize":pcap_file.size}
        st.write(file_details)
        domain_name = st.text_input("Enter the domain name to search : ")
        packets = rdpcap(pcap_file)

        # if(st.button('Submit')):
        #     result = domain_name.title()
        #     st.write(result)
        #     domain_search(result, packets)
        #     st.success(result)
        
        process_src_IP(packets)
        read_pcap(packets)
        
  
  else:
    st.write("Incorrect file format")

if __name__=='__main__':
  main()
