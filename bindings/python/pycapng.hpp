#ifndef _PCAPNGPP_H_
#define _PCAPNGPP_H_

#include <stdio.h>

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
  py::bytes BuildDNSQuery(const std::string &src_mac,
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
  int WritePacketTime(py::bytes data, uint32_t timestamp);
  int WriteCustom(uint32_t pen, py::bytes data, const std::string &comment);
  int ForeachPacket(const py::object &func);
  //
  int get_compression_level(void) { return compression_level; };
  char *get_filename(void) { return filename; };
private:
  FILE *_fp;
  char *filename;
  int compression_level;

  static int foreach_packet_cb(uint32_t block_counter, uint32_t block_type, uint32_t block_total_length, unsigned char *data, void *userdata);
};

#endif // _PCAPNGPP_H_
