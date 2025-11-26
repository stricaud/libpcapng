#include <stdio.h>
#include <stdlib.h>

#include <libpcapng/libpcapng.h>

#include <pybind11/pybind11.h>
#include <pybind11/functional.h>
#include <pybind11/stl.h>

#include "pycapng.hpp"

namespace py = pybind11;

PcapNG::PcapNG(void) {
  filename = NULL;
  
  // compression_level = 10;
  compression_level = 0;
}

PcapNG::~PcapNG(void) {
}

int PcapNG::OpenFile(const char *pathname, const char *mode)
{
  unsigned char *buffer;
  size_t buffer_size;

  if (!strcmp(mode, "w")) {
    _fp = fopen(pathname, "wb");
    if (!_fp) {
      fprintf(stderr, "Could not open file '%s' for writing!\n", pathname);
      return -1;
    }

    libpcapng_write_header_to_file(_fp);
  
    return 0;
  }

  if (!strcmp(mode, "a")) {
    _fp = fopen(pathname, "a");
    if (!_fp) {
      fprintf(stderr, "Could not open file '%s' for appending!\n", pathname);
      return -1;
    }

    return 0;
  }
  
  if (!strcmp(mode, "r")) {
    _fp = fopen(pathname, "rb");
    if (!_fp) {
      fprintf(stderr, "Could not open file '%s' for reading!\n", pathname);
      return -1;
    }
    return 0;
  }

  fprintf(stderr, "Error opening file '%s' with mode '%s'. Supported modes are 'r' or 'w'.", pathname, mode);
  return -1;
}

int PcapNG::OpenFileLinkType(const char *pathname, const char *mode, uint16_t linktype)
{
  unsigned char *buffer;
  size_t buffer_size;

  if (!strcmp(mode, "w")) {
    _fp = fopen(pathname, "wb");
    if (!_fp) {
      fprintf(stderr, "Could not open file '%s' for writing!\n", pathname);
      return -1;
    }

    libpcapng_write_header_to_file_with_linktype(_fp, linktype);
  
    return 0;
  }

  if (!strcmp(mode, "a")) {
    _fp = fopen(pathname, "a");
    if (!_fp) {
      fprintf(stderr, "Could not open file '%s' for appending!\n", pathname);
      return -1;
    }

    return 0;
  }
  
  if (!strcmp(mode, "r")) {
    _fp = fopen(pathname, "rb");
    if (!_fp) {
      fprintf(stderr, "Could not open file '%s' for reading!\n", pathname);
      return -1;
    }
    return 0;
  }

  fprintf(stderr, "Error opening file '%s' with mode '%s'. Supported modes are 'r' or 'w'.", pathname, mode);
  return -1;
}

int PcapNG::CloseFile(void)
{
  fflush(_fp);
  fclose(_fp);
  return 0;
}

int PcapNG::WritePacket(py::bytes data, const std::string &comment)  
{
  py::buffer_info info(py::buffer(data).request());
  uint8_t *data_bytes = reinterpret_cast<uint8_t *>(info.ptr);
  size_t data_len = static_cast<size_t>(info.size);

  libpcapng_write_enhanced_packet_to_file(_fp, data_bytes, data_len);

  return 0;
}

int PcapNG::WriteTcpPacket(const std::string &src_mac, const std::string &dst_mac,
			   const std::string &src_ip, const std::string &dst_ip,
			   uint32_t src_port, uint32_t dst_port,
			   uint32_t seqnum, uint32_t ack, uint8_t flags, py::bytes data)  
{
  py::buffer_info info(py::buffer(data).request());
  uint8_t *data_bytes = reinterpret_cast<uint8_t *>(info.ptr);
  size_t data_len = static_cast<size_t>(info.size);

  uint8_t frame[65536];
  size_t frame_len;

  int retval;

  uint8_t client_mac[6];
  retval = libpcapng_mac_str_to_bytes(src_mac.c_str(), client_mac);
  if (retval) {
    fprintf(stderr, "Could not convert src_mac '%s' to a valid mac address!\n", src_mac.c_str());
    return -1;
  }
  uint8_t server_mac[6];
  retval = libpcapng_mac_str_to_bytes(dst_mac.c_str(), server_mac);
  if (retval) {
    fprintf(stderr, "Could not convert dst_mac '%s' to a valid mac address!\n", dst_mac.c_str());
    return -1;
  }
  uint32_t client_ip = libpcapng_ipv4_to_host_order(src_ip.c_str());
  uint32_t server_ip = libpcapng_ipv4_to_host_order(dst_ip.c_str());

  if (data_len > 0) {
    libpcapng_tcp_packet_build(client_mac, server_mac, client_ip, server_ip, src_port, dst_port, seqnum, 0, 0x02, data_bytes, data_len, frame, &frame_len);
    libpcapng_write_enhanced_packet_to_file(_fp, frame, frame_len);
  } else {
    libpcapng_tcp_packet_build(client_mac, server_mac, client_ip, server_ip, src_port, dst_port, seqnum, 0, 0x02, NULL, 0, frame, &frame_len);
    libpcapng_write_enhanced_packet_to_file(_fp, frame, frame_len);
  }

  return 0;
}

int PcapNG::WritePacketTime(py::bytes data, uint32_t timestamp)
{
  py::buffer_info info(py::buffer(data).request());
  uint8_t *data_bytes = reinterpret_cast<uint8_t *>(info.ptr);
  size_t data_len = static_cast<size_t>(info.size);

  libpcapng_write_enhanced_packet_with_time_to_file(_fp, data_bytes, data_len, timestamp);

  return 0;
}

int PcapNG::WriteCustom(uint32_t pen, py::bytes data, const std::string &comment)  
{
  unsigned char *buffer;
  size_t buffer_size;

  py::buffer_info info(py::buffer(data).request());
  uint8_t *data_bytes = reinterpret_cast<uint8_t *>(info.ptr);
  size_t data_len = static_cast<size_t>(info.size);
  
  buffer_size = libpcapng_custom_data_block_size(data_len);
  buffer = (unsigned char *)malloc(buffer_size);
  libpcapng_custom_data_block_write(pen, data_bytes, data_len, buffer);
  fwrite(buffer, buffer_size, 1, _fp);

  return 0;
}

int PcapNG::foreach_packet_cb(uint32_t block_counter, uint32_t block_type, uint32_t block_total_length, unsigned char *data, void *userdata)
{
  py::object cb_func = *(py::object *)userdata;

  uint32_t start_offset = libpcapng_custom_data_block_start_offset();
  uint32_t data_length = libpcapng_custom_data_block_data_length(block_total_length);
  
  int padded = libpcapng_padded_count(&data[start_offset], data_length);

  // The function sometimes cut the last }
  
  // FIXME: We just send the data but we will need to make this an object where we can retrieve the pen etc.
  cb_func(block_counter, block_type, block_total_length, py::bytes((const char *)&data[start_offset],
								   data_length - padded));

  return 0;
}

int PcapNG::ForeachPacket(const py::object &func)
{
  return libpcapng_fp_read(_fp, foreach_packet_cb, (void *)&func);
}

PYBIND11_MODULE(pycapng, m) {
    m.doc() = "libpcapng Python Bindings";

    // Our constants
    m.attr("ENHANCED_PACKET_BLOCK") = py::int_(PCAPNG_ENHANCED_PACKET_BLOCK);
    m.attr("CUSTOM_DATA_BLOCK") = py::int_(PCAPNG_CUSTOM_DATA_BLOCK);
    m.attr("INTERFACE_DESCRIPTION_BLOCK") = py::int_(PCAPNG_INTERFACE_DESCRIPTION_BLOCK);
    m.attr("PACKET_BLOCK") = py::int_(PCAPNG_PACKET_BLOCK);
    m.attr("SIMPLE_PACKET_BLOCK") = py::int_(PCAPNG_SIMPLE_PACKET_BLOCK);
    m.attr("NAME_RESOLUTION_BLOCK") = py::int_(PCAPNG_NAME_RESOLUTION_BLOCK);
    m.attr("INTERFACE_STATISTICS_BLOCK") = py::int_(PCAPNG_INTERFACE_STATISTICS_BLOCK);
    m.attr("ENHANCED_PACKET_BLOCK") = py::int_(PCAPNG_ENHANCED_PACKET_BLOCK);
    m.attr("IRIG_TIMESTAMP_BLOCK") = py::int_(PCAPNG_IRIG_TIMESTAMP_BLOCK);
    m.attr("ARINC_429_AFDX_ENCAP_BLOCK") = py::int_(PCAPNG_ARINC_429_AFDX_ENCAP_BLOCK);
    m.attr("SYSTEMD_JOURNAL_EXPORT_BLOCK") = py::int_(PCAPNG_SYSTEMD_JOURNAL_EXPORT_BLOCK);
    m.attr("DECRYPTION_SECRETS_BLOCK") = py::int_(PCAPNG_DECRYPTION_SECRETS_BLOCK);
    m.attr("HONE_PROJECT_MACHINE_INFO_BLOCK") = py::int_(PCAPNG_HONE_PROJECT_MACHINE_INFO_BLOCK);
    m.attr("HONE_PROJECT_CONNECTION_EVENT_BLOCK") = py::int_(PCAPNG_HONE_PROJECT_CONNECTION_EVENT_BLOCK);
    m.attr("SYSDIG_MACHINE_INFO_BLOCK") = py::int_(PCAPNG_SYSDIG_MACHINE_INFO_BLOCK);
    m.attr("SYSDIG_PROCESS_INFO_V1_BLOCK") = py::int_(PCAPNG_SYSDIG_PROCESS_INFO_V1_BLOCK);
    m.attr("SYSDIG_FD_LIST_BLOCK") = py::int_(PCAPNG_SYSDIG_FD_LIST_BLOCK);
    m.attr("SYSDIG_EVENT_BLOCK") = py::int_(PCAPNG_SYSDIG_EVENT_BLOCK);
    m.attr("SYSDIG_INTERFACE_LIST_BLOCK") = py::int_(PCAPNG_SYSDIG_INTERFACE_LIST_BLOCK);
    m.attr("SYSDIG_USER_LIST_BLOCK") = py::int_(PCAPNG_SYSDIG_USER_LIST_BLOCK);
    m.attr("SYSDIG_PROCESS_INFO_V2_BLOCK") = py::int_(PCAPNG_SYSDIG_PROCESS_INFO_V2_BLOCK);
    m.attr("SYSDIG_EVENT_WITH_FLAGS_BLOCK") = py::int_(PCAPNG_SYSDIG_EVENT_WITH_FLAGS_BLOCK);
    m.attr("SYSDIG_PROCESS_INFO_V3_BLOCK") = py::int_(PCAPNG_SYSDIG_PROCESS_INFO_V3_BLOCK);
    m.attr("SYSDIG_PROCESS_INFO_V4_BLOCK") = py::int_(PCAPNG_SYSDIG_PROCESS_INFO_V4_BLOCK);
    m.attr("SYSDIG_PROCESS_INFO_V5_BLOCK") = py::int_(PCAPNG_SYSDIG_PROCESS_INFO_V5_BLOCK);
    m.attr("SYSDIG_PROCESS_INFO_V6_BLOCK") = py::int_(PCAPNG_SYSDIG_PROCESS_INFO_V6_BLOCK);
    m.attr("SYSDIG_PROCESS_INFO_V7_BLOCK") = py::int_(PCAPNG_SYSDIG_PROCESS_INFO_V7_BLOCK);
    m.attr("CUSTOM_DATA_BLOCK") = py::int_(PCAPNG_CUSTOM_DATA_BLOCK);
    m.attr("CUSTOM_DATA_BLOCK_NOCOPY") = py::int_(PCAPNG_CUSTOM_DATA_BLOCK_NOCOPY);
    m.attr("SECTION_HEADER_BLOCK") = py::int_(PCAPNG_SECTION_HEADER_BLOCK);
    m.attr("TLS_KEY_LOG") = py::int_(PCAPNG_TLS_KEY_LOG);
    m.attr("WIREGUARD_KEY_LOG") = py::int_(PCAPNG_WIREGUARD_KEY_LOG);
    m.attr("ZIGBEE_NWK_KEY") = py::int_(PCAPNG_ZIGBEE_NWK_KEY);
    m.attr("ZIGBEE_APS_KEY") = py::int_(PCAPNG_ZIGBEE_APS_KEY);
    // Link types
    m.attr("LINKTYPE_NULL") = py::int_(LINKTYPE_NULL);
    m.attr("LINKTYPE_ETHERNET") = py::int_(LINKTYPE_ETHERNET);
    m.attr("LINKTYPE_AX25") = py::int_(LINKTYPE_AX25);
    m.attr("LINKTYPE_IEEE802_5") = py::int_(LINKTYPE_IEEE802_5);
    m.attr("LINKTYPE_ARCNET_BSD") = py::int_(LINKTYPE_ARCNET_BSD);
    m.attr("LINKTYPE_SLIP") = py::int_(LINKTYPE_SLIP);
    m.attr("LINKTYPE_PPP") = py::int_(LINKTYPE_PPP);
    m.attr("LINKTYPE_FDDI") = py::int_(LINKTYPE_FDDI);
    m.attr("LINKTYPE_PPP_HDLC") = py::int_(LINKTYPE_PPP_HDLC);
    m.attr("LINKTYPE_PPP_ETHER") = py::int_(LINKTYPE_PPP_ETHER);
    m.attr("LINKTYPE_ATM_RFC1483") = py::int_(LINKTYPE_ATM_RFC1483);
    m.attr("LINKTYPE_RAW") = py::int_(LINKTYPE_RAW);
    m.attr("LINKTYPE_C_HDLC") = py::int_(LINKTYPE_C_HDLC);
    m.attr("LINKTYPE_IEEE802_11") = py::int_(LINKTYPE_IEEE802_11);
    m.attr("LINKTYPE_FRELAY") = py::int_(LINKTYPE_FRELAY);
    m.attr("LINKTYPE_LOOP") = py::int_(LINKTYPE_LOOP);
    m.attr("LINKTYPE_LINUX_SLL") = py::int_(LINKTYPE_LINUX_SLL);
    m.attr("LINKTYPE_LTALK") = py::int_(LINKTYPE_LTALK);
    m.attr("LINKTYPE_PFLOG") = py::int_(LINKTYPE_PFLOG);
    m.attr("LINKTYPE_IEEE802_11_PRISM") = py::int_(LINKTYPE_IEEE802_11_PRISM);
    m.attr("LINKTYPE_IP_OVER_FC") = py::int_(LINKTYPE_IP_OVER_FC);
    m.attr("LINKTYPE_SUNATM") = py::int_(LINKTYPE_SUNATM);
    m.attr("LINKTYPE_IEEE802_11_RADIOTAP") = py::int_(LINKTYPE_IEEE802_11_RADIOTAP);
    m.attr("LINKTYPE_ARCNET_LINUX") = py::int_(LINKTYPE_ARCNET_LINUX);
    m.attr("LINKTYPE_APPLE_IP_OVER_IEEE1394") = py::int_(LINKTYPE_APPLE_IP_OVER_IEEE1394);
    m.attr("LINKTYPE_MTP2_WITH_PHDR") = py::int_(LINKTYPE_MTP2_WITH_PHDR);
    m.attr("LINKTYPE_MTP2") = py::int_(LINKTYPE_MTP2);
    m.attr("LINKTYPE_MTP3") = py::int_(LINKTYPE_MTP3);
    m.attr("LINKTYPE_SCCP") = py::int_(LINKTYPE_SCCP);
    m.attr("LINKTYPE_DOCSIS") = py::int_(LINKTYPE_DOCSIS);
    m.attr("LINKTYPE_LINUX_IRDA") = py::int_(LINKTYPE_LINUX_IRDA);
    m.attr("LINKTYPE_IEEE802_11_AVS") = py::int_(LINKTYPE_IEEE802_11_AVS);
    m.attr("LINKTYPE_BACNET_MS_TP") = py::int_(LINKTYPE_BACNET_MS_TP);
    m.attr("LINKTYPE_PPP_PPPD") = py::int_(LINKTYPE_PPP_PPPD);
    m.attr("LINKTYPE_GPRS_LLC") = py::int_(LINKTYPE_GPRS_LLC);
    m.attr("LINKTYPE_GPF_T") = py::int_(LINKTYPE_GPF_T);
    m.attr("LINKTYPE_GPF_F") = py::int_(LINKTYPE_GPF_F);
    m.attr("LINKTYPE_LINUX_LAPD") = py::int_(LINKTYPE_LINUX_LAPD);
    m.attr("LINKTYPE_MFR") = py::int_(LINKTYPE_MFR);
    m.attr("LINKTYPE_BLUETOOTH_HCI_H4") = py::int_(LINKTYPE_BLUETOOTH_HCI_H4);
    m.attr("LINKTYPE_USB_LINUX") = py::int_(LINKTYPE_USB_LINUX);
    m.attr("LINKTYPE_PPI") = py::int_(LINKTYPE_PPI);
    m.attr("LINKTYPE_IEEE802_15_4_WITHFCS") = py::int_(LINKTYPE_IEEE802_15_4_WITHFCS);
    m.attr("LINKTYPE_SITA") = py::int_(LINKTYPE_SITA);
    m.attr("LINKTYPE_ERF") = py::int_(LINKTYPE_ERF);
    m.attr("LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR") = py::int_(LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR);
    m.attr("LINKTYPE_AX25_KISS") = py::int_(LINKTYPE_AX25_KISS);
    m.attr("LINKTYPE_LAPD") = py::int_(LINKTYPE_LAPD);
    m.attr("LINKTYPE_PPP_WITH_DIR") = py::int_(LINKTYPE_PPP_WITH_DIR);
    m.attr("LINKTYPE_C_HDLC_WITH_DIR") = py::int_(LINKTYPE_C_HDLC_WITH_DIR);
    m.attr("LINKTYPE_FRELAY_WITH_DIR") = py::int_(LINKTYPE_FRELAY_WITH_DIR);
    m.attr("LINKTYPE_LAPB_WITH_DIR") = py::int_(LINKTYPE_LAPB_WITH_DIR);
    m.attr("LINKTYPE_IPMB_LINUX") = py::int_(LINKTYPE_IPMB_LINUX);
    m.attr("LINKTYPE_IEEE802_15_4_NONASK_PHY") = py::int_(LINKTYPE_IEEE802_15_4_NONASK_PHY);
    m.attr("LINKTYPE_USB_LINUX_MMAPPED") = py::int_(LINKTYPE_USB_LINUX_MMAPPED);
    m.attr("LINKTYPE_FC_2") = py::int_(LINKTYPE_FC_2);
    m.attr("LINKTYPE_FC_2_WITH_FRAME_DELIMS") = py::int_(LINKTYPE_FC_2_WITH_FRAME_DELIMS);
    m.attr("LINKTYPE_IPNET") = py::int_(LINKTYPE_IPNET);
    m.attr("LINKTYPE_CAN_SOCKETCAN") = py::int_(LINKTYPE_CAN_SOCKETCAN);
    m.attr("LINKTYPE_IPV4") = py::int_(LINKTYPE_IPV4);
    m.attr("LINKTYPE_IPV6") = py::int_(LINKTYPE_IPV6);
    m.attr("LINKTYPE_IEEE802_15_4_NOFCS") = py::int_(LINKTYPE_IEEE802_15_4_NOFCS);
    m.attr("LINKTYPE_DBUS") = py::int_(LINKTYPE_DBUS);
    m.attr("LINKTYPE_DVB_CI") = py::int_(LINKTYPE_DVB_CI);
    m.attr("LINKTYPE_MUX27010") = py::int_(LINKTYPE_MUX27010);
    m.attr("LINKTYPE_STANAG_5066_D_PDU") = py::int_(LINKTYPE_STANAG_5066_D_PDU);
    m.attr("LINKTYPE_NFLOG") = py::int_(LINKTYPE_NFLOG);
    m.attr("LINKTYPE_NETANALYZER") = py::int_(LINKTYPE_NETANALYZER);
    m.attr("LINKTYPE_NETANALYZER_TRANSPARENT") = py::int_(LINKTYPE_NETANALYZER_TRANSPARENT);
    m.attr("LINKTYPE_IPOIB") = py::int_(LINKTYPE_IPOIB);
    m.attr("LINKTYPE_MPEG_2_TS") = py::int_(LINKTYPE_MPEG_2_TS);
    m.attr("LINKTYPE_NG40") = py::int_(LINKTYPE_NG40);
    m.attr("LINKTYPE_NFC_LLCP") = py::int_(LINKTYPE_NFC_LLCP);
    m.attr("LINKTYPE_INFINIBAND") = py::int_(LINKTYPE_INFINIBAND);
    m.attr("LINKTYPE_SCTP") = py::int_(LINKTYPE_SCTP);
    m.attr("LINKTYPE_USBPCAP") = py::int_(LINKTYPE_USBPCAP);
    m.attr("LINKTYPE_RTAC_SERIAL") = py::int_(LINKTYPE_RTAC_SERIAL);
    m.attr("LINKTYPE_BLUETOOTH_LE_LL") = py::int_(LINKTYPE_BLUETOOTH_LE_LL);
    m.attr("LINKTYPE_NETLINK") = py::int_(LINKTYPE_NETLINK);
    m.attr("LINKTYPE_BLUETOOTH_LINUX_MONITOR") = py::int_(LINKTYPE_BLUETOOTH_LINUX_MONITOR);
    m.attr("LINKTYPE_BLUETOOTH_BREDR_BB") = py::int_(LINKTYPE_BLUETOOTH_BREDR_BB);
    m.attr("LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR") = py::int_(LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR);
    m.attr("LINKTYPE_PROFIBUS_DL") = py::int_(LINKTYPE_PROFIBUS_DL);
    m.attr("LINKTYPE_PKTAP") = py::int_(LINKTYPE_PKTAP);
    m.attr("LINKTYPE_EPON") = py::int_(LINKTYPE_EPON);
    m.attr("LINKTYPE_IPMI_HPM_2") = py::int_(LINKTYPE_IPMI_HPM_2);
    m.attr("LINKTYPE_ZWAVE_R1_R2") = py::int_(LINKTYPE_ZWAVE_R1_R2);
    m.attr("LINKTYPE_ZWAVE_R3") = py::int_(LINKTYPE_ZWAVE_R3);
    m.attr("LINKTYPE_WATTSTOPPER_DLM") = py::int_(LINKTYPE_WATTSTOPPER_DLM);
    m.attr("LINKTYPE_ISO_14443") = py::int_(LINKTYPE_ISO_14443);
    m.attr("LINKTYPE_RDS") = py::int_(LINKTYPE_RDS);
    m.attr("LINKTYPE_USB_DARWIN") = py::int_(LINKTYPE_USB_DARWIN);
    m.attr("LINKTYPE_SDLC") = py::int_(LINKTYPE_SDLC);
    m.attr("LINKTYPE_LORATAP") = py::int_(LINKTYPE_LORATAP);
    m.attr("LINKTYPE_VSOCK") = py::int_(LINKTYPE_VSOCK);
    m.attr("LINKTYPE_NORDIC_BLE") = py::int_(LINKTYPE_NORDIC_BLE);
    m.attr("LINKTYPE_DOCSIS31_XRA31") = py::int_(LINKTYPE_DOCSIS31_XRA31);
    m.attr("LINKTYPE_ETHERNET_MPACKET") = py::int_(LINKTYPE_ETHERNET_MPACKET);
    m.attr("LINKTYPE_DISPLAYPORT_AUX") = py::int_(LINKTYPE_DISPLAYPORT_AUX);
    m.attr("LINKTYPE_LINUX_SLL2") = py::int_(LINKTYPE_LINUX_SLL2);
    m.attr("LINKTYPE_OPENVIZSLA") = py::int_(LINKTYPE_OPENVIZSLA);
    m.attr("LINKTYPE_EBHSCR") = py::int_(LINKTYPE_EBHSCR);
    m.attr("LINKTYPE_VPP_DISPATCH") = py::int_(LINKTYPE_VPP_DISPATCH);
    m.attr("LINKTYPE_DSA_TAG_BRCM") = py::int_(LINKTYPE_DSA_TAG_BRCM);
    m.attr("LINKTYPE_DSA_TAG_BRCM_PREPEND") = py::int_(LINKTYPE_DSA_TAG_BRCM_PREPEND);
    m.attr("LINKTYPE_IEEE802_15_4_TAP") = py::int_(LINKTYPE_IEEE802_15_4_TAP);
    m.attr("LINKTYPE_DSA_TAG_DSA") = py::int_(LINKTYPE_DSA_TAG_DSA);
    m.attr("LINKTYPE_DSA_TAG_EDSA") = py::int_(LINKTYPE_DSA_TAG_EDSA);
    m.attr("LINKTYPE_ELEE") = py::int_(LINKTYPE_ELEE);
    m.attr("LINKTYPE_Z_WAVE_SERIAL") = py::int_(LINKTYPE_Z_WAVE_SERIAL);
    m.attr("LINKTYPE_USB_2_0") = py::int_(LINKTYPE_USB_2_0);
    m.attr("LINKTYPE_ATSC_ALP") = py::int_(LINKTYPE_ATSC_ALP);
   
    py::class_<PcapNG>(m, "PcapNG")
      .def(py::init<>())
      .def("OpenFile", &PcapNG::OpenFile)
      .def("OpenFileLinkType", &PcapNG::OpenFileLinkType)
      .def("CloseFile", &PcapNG::CloseFile)
      .def("WriteCustom", &PcapNG::WriteCustom)
      .def("WritePacket", &PcapNG::WritePacket)
      .def("WriteTcpPacket", &PcapNG::WriteTcpPacket)
      .def("WritePacketTime", &PcapNG::WritePacketTime)
      .def("ForeachPacket", &PcapNG::ForeachPacket);
}



