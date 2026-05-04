#ifndef _PCAPNGPP_H_
#define _PCAPNGPP_H_

#include <stdio.h>
#include <string.h>

#include <libpcapng/protocols/rdp.h>

#include <pybind11/pybind11.h>
#include <pybind11/functional.h>

// Maximum safe DNS packet size (standard DNS UDP limit)
#define DNS_MAX_SIZE 512

namespace py = pybind11;

class PcapNG {
public:
  PcapNG(void);
  ~PcapNG(void);
  int OpenFile(const char *pathname, const char *mode);
  int OpenFileLinkType(const char *pathname, const char *mode, uint16_t linktype);
  int CloseFile(void);
  int WritePacket(py::bytes data, const std::string &comment);
  int WriteTcpPacket(const std::string &src_mac, const std::string &dst_mac,
		     const std::string &src_ip, const std::string &dst_ip,
		     uint32_t src_port, uint32_t dst_port,
		     uint32_t seqnum, uint32_t ack, uint8_t flags, py::bytes data);
  py::bytes BuildTcpPacket(const std::string &src_mac,
			   const std::string &dst_mac,
			   const std::string &src_ip,
			   const std::string &dst_ip,
			   uint32_t src_port,
			   uint32_t dst_port,
			   uint32_t seqnum,
			   uint32_t ack,
			   uint8_t flags,
			   py::bytes data);
  py::bytes BuildUdpPacket(const std::string &src_mac,
			   const std::string &dst_mac,
			   const std::string &src_ip,
			   const std::string &dst_ip,
			   uint32_t src_port,
			   uint32_t dst_port,
			   py::bytes data);
  py::bytes BuildIcmpPacket(const std::string &src_mac,
			    const std::string &dst_mac,
			    const std::string &src_ip,
			    const std::string &dst_ip,
			    uint8_t icmp_type, uint8_t icmp_code,
			    uint16_t identifier, uint16_t sequence,
			    py::bytes data);
  py::bytes BuildDnsQuery(const std::string &src_mac,
			  const std::string &dst_mac,
			  const std::string &src_ip,
			  const std::string &dst_ip,
			  uint32_t src_port,
			  uint32_t dst_port,
			  uint16_t transaction_id,
			  const std::string &domain,
			  const std::string &qtype,
			  const std::string &qclass);
  py::bytes BuildDNSResponse(const std::string &src_mac,
			     const std::string &dst_mac,
			     const std::string &src_ip,
			     const std::string &dst_ip,
			     uint32_t src_port,
			     uint32_t dst_port,
			     uint16_t transaction_id,
			     const std::string &domain,
			     const std::string &qtype,
			     const std::string &response_ip);
  py::bytes BuildDhcpDiscover(const std::string &src_mac,
			      const std::string &src_ip,
			      uint32_t src_port,
			      uint32_t dst_port,
			      uint16_t xid);
  py::bytes BuildDhcpOffer(const std::string &src_mac, const std::string &dst_mac,
			   const std::string &src_ip, const std::string &offered_ip,
			   uint16_t xid,
			   uint32_t src_port,
			   uint32_t dst_port);
  py::bytes BuildNtpRequest(const std::string &src_mac, const std::string &dst_mac,
			    const std::string &src_ip, const std::string &dst_ip,
			    uint32_t src_port, uint32_t dst_port);
  py::bytes  BuildNtpReply(const std::string &src_mac, const std::string &dst_mac,
			   const std::string &src_ip, const std::string &dst_ip,
			   uint32_t src_port, uint32_t dst_port, py::bytes ntp_request);
  py::bytes  BuildTlsClientHello(const std::string &src_mac, const std::string &dst_mac,
				 const std::string &src_ip, const std::string &dst_ip,
				 uint32_t src_port, uint32_t dst_port);
  py::bytes  BuildTlsServerHello(const std::string &src_mac, const std::string &dst_mac,
				 const std::string &src_ip, const std::string &dst_ip,
				 uint32_t src_port, uint32_t dst_port);
  py::bytes  BuildTlsCertificate(const std::string &cert);
  py::bytes  BuildTlsFinished();
  py::bytes  BuildTlsApplicationData(const std::string &src_mac, const std::string &dst_mac,
				     const std::string &src_ip, const std::string &dst_ip,
				     uint32_t src_port, uint32_t dst_port, py::bytes tls_appdata);
  
  int WritePacketTime(py::bytes data, uint32_t timestamp);
  int WriteCustom(uint32_t pen, py::bytes data, const std::string &comment);
  int ForeachPacket(const py::object &func);

  /* ── RDP ── */
  py::bytes BuildRdpConnectionRequest(const std::string &src_mac,
                                      const std::string &dst_mac,
                                      const std::string &src_ip,
                                      const std::string &dst_ip,
                                      uint32_t src_port, uint32_t dst_port,
                                      const std::string &username,
                                      const std::string &domain,
                                      uint32_t requested_protocol,
                                      int use_tls);

  py::bytes BuildRdpConnectionConfirm(const std::string &src_mac,
                                      const std::string &dst_mac,
                                      const std::string &src_ip,
                                      const std::string &dst_ip,
                                      uint32_t src_port, uint32_t dst_port,
                                      uint32_t selected_protocol);

  /* Simulate a full RDP session (login → activity → logout) into the open file */
  void SimulateRdpLogin(const std::string &c_mac, const std::string &s_mac,
                        const std::string &c_ip,  const std::string &s_ip,
                        uint32_t c_port, uint32_t s_port,
                        const std::string &username,
                        const std::string &domain,
                        const std::string &password,
                        uint32_t user_id,
                        uint32_t desktop_width, uint32_t desktop_height,
                        int use_tls);

  void SimulateRdpKeyboard(const std::string &c_mac, const std::string &s_mac,
                           const std::string &c_ip,  const std::string &s_ip,
                           uint32_t c_port, uint32_t s_port,
                           uint16_t keycode, int use_tls);

  void SimulateRdpMouse(const std::string &c_mac, const std::string &s_mac,
                        const std::string &c_ip,  const std::string &s_ip,
                        uint32_t c_port, uint32_t s_port,
                        uint16_t x, uint16_t y, int click, int use_tls);

  void SimulateRdpClipboard(const std::string &c_mac, const std::string &s_mac,
                             const std::string &c_ip,  const std::string &s_ip,
                             uint32_t c_port, uint32_t s_port,
                             py::bytes data, int use_tls);

  void SimulateRdpLogout(const std::string &c_mac, const std::string &s_mac,
                         const std::string &c_ip,  const std::string &s_ip,
                         uint32_t c_port, uint32_t s_port, int use_tls);
  //
  int get_compression_level(void) { return compression_level; };
  char *get_filename(void) { return filename; };
private:
  FILE *_fp;
  char *filename;
  int compression_level;

  /* RDP per-file session state (seq numbers advance across calls) */
  libpcapng_rdp_session_t _rdp_sess;
  libpcapng_rdp_config_t  _rdp_cfg;
  uint8_t _rdp_c_mac[6];
  uint8_t _rdp_s_mac[6];
  uint32_t _rdp_c_ip;
  uint32_t _rdp_s_ip;
  uint16_t _rdp_c_port;
  uint16_t _rdp_s_port;

  static int foreach_packet_cb(uint32_t block_counter, uint32_t block_type, uint32_t block_total_length, unsigned char *data, void *userdata);
};

#endif // _PCAPNGPP_H_
