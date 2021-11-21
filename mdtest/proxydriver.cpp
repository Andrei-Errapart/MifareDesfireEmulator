#include <stdexcept>	// std::runtime_error
#include <stdio.h>	// printf
#include <unistd.h>	// close
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>	// gethostbyname
#include <string.h>	// memset
#include <arpa/inet.h>	// inet_addr
#include <alloca.h>	// alloca
#include <stdlib.h>	// malloc

#include <nfc/nfc.h>
#include <drivers.h>
#include <nfc-internal.h>

#include "mdcomm.pb.h"

#include <google/protobuf/io/coded_stream.h>	// Coded(Input|Output)Stream
#include <google/protobuf/io/zero_copy_stream.h>	// 
#include <google/protobuf/io/zero_copy_stream_impl.h>	// File(Input|Output)Stream



static const char*	TARGET_HOSTNAME = "192.168.5.107";
static const int	TARGET_PORT = 1555;
extern struct nfc_driver proxydriver_driver;



// ==================================================================
static void
_write_message(
	int socket,
	const communication::MessageToSlave& message)
{
#if (0)
	google::protobuf::uint32 message_length = message.ByteSize();
	int prefix_length = sizeof(message_length);
	int buffer_length = prefix_length + message_length;
	google::protobuf::uint8 buffer[buffer_length];

	google::protobuf::io::ArrayOutputStream array_output(buffer, buffer_length);
	google::protobuf::io::CodedOutputStream coded_output(&array_output);

	coded_output.WriteLittleEndian32(message_length);
	message.SerializeToCodedStream(&coded_output);

	int sent_bytes = write(socket, buffer, buffer_length);
	if (sent_bytes != buffer_length) {
		return false;
	}
	return true;
#endif
	google::protobuf::io::FileOutputStream		raw_out(socket,0);
	google::protobuf::io::CodedOutputStream		coded_out(&raw_out);
	coded_out.WriteVarint32(message.ByteSize());
	message.SerializeToCodedStream(&coded_out);
}

#if (0)
// ==================================================================
static bool
_read_message(int socket, my_protobuf::Message *message)
{
	google::protobuf::uint32 message_length;
	int prefix_length = sizeof(message_length);
	google::protobuf::uint8 prefix[prefix_length];

	if (prefix_length != read(socket, prefix, prefix_length)) {
	return false;
	}
	google::protobuf::io::CodedInputStream::ReadLittleEndian32FromArray(prefix,
	&message_length);

	google::protobuf::uint8 buffer[message_length];
	if (message_length != read(socket, buffer, message_length)) {
	return false;
	}
	google::protobuf::io::ArrayInputStream array_input(buffer, message_length);
	google::protobuf::io::CodedInputStream coded_input(&array_input);

	if (!message->ParseFromCodedStream(&coded_input)) {
	return false;
	}
	return true;
}
#endif


// ==================================================================
#if (0)
// Google.ProtocolBuffers.CodedInputStream
static uint32_t
_readRawVarint32(int fd)
{
	uint32_t num = 0;
	int i;
	for (i = 0; i < 32; i += 7)
	{
		uint8_t	num2;
		do
		{
			int r = read(fd, &num2, sizeof(num2));
			if (r<0)
			{
				throw std::runtime_error("proxydriver: Peer disconnected while reading.\n");
			}
		} while (r==0);
		num |= (num2 & 0x7F) << i;
		if ((num2 & 0x80) == 0)
		{
			return (uint)num;
		}
	}
	while (i < 64)
	{
		int num3 = input.ReadByte();
		if (num3 == -1)
		{
			throw InvalidProtocolBufferException.TruncatedMessage();
		}
		if ((num3 & 128) == 0)
		{
			return (uint)num;
		}
		i += 7;
	}
	throw InvalidProtocolBufferException.MalformedVarint();
}
#else
static int8_t
_read_byte(int fd)
{
	int8_t		b = 0;
	const int	r = read(fd, &b, sizeof(b));
	switch (r)
	{
	case 0:
		throw std::runtime_error("proxydriver: Peer disconnected while reading.\n");
	case sizeof(b):
		return b;
	default:
		throw std::runtime_error("proxydriver: Error reading from the peer.\n");
	}
}
/**
* Read a raw Varint from the stream. If larger than 32 bits, discard the
* upper bits.
*/
static uint32_t
_read_raw_varint32(int fd)
{
	int8_t tmp = _read_byte(fd);
	if (tmp >= 0) {
		return tmp;
	}
	int result = tmp & 0x7f;
	if ((tmp = _read_byte(fd)) >= 0) {
		result |= tmp << 7;
	} else {
		result |= (tmp & 0x7f) << 7;
		if ((tmp = _read_byte(fd)) >= 0) {
			result |= tmp << 14;
		} else {
			result |= (tmp & 0x7f) << 14;
			if ((tmp = _read_byte(fd)) >= 0) {
				result |= tmp << 21;
			} else {
				result |= (tmp & 0x7f) << 21;
				result |= (tmp = _read_byte(fd)) << 28;
				if (tmp < 0) {
					// Discard upper 32 bits.
					for (int i = 0; i < 5; i++) {
						if (_read_byte(fd) >= 0)
							return result;
					}
					throw std::runtime_error("proxydriver: Error reading from the peer too much.\n");
				}
			}
		}
	}
	return result;
}
#endif


// ==================================================================
class ProxyDriverData {
public:
	ProxyDriverData(int sockfd) : _id(++_prev_id), _sockfd(sockfd)
	{
	}
	~ProxyDriverData()
	{
		if (_sockfd>0)
		{
			close(_sockfd);
		}
		_sockfd = -1;
	}

	unsigned int id() const
	{
		return _id;
	}

	void Write(const communication::MessageToSlave& message)
	{
	#if (0)
		google::protobuf::uint32 message_length = message.ByteSize();
		int prefix_length = sizeof(message_length);
		int buffer_length = prefix_length + message_length;
		google::protobuf::uint8 buffer[buffer_length];

		google::protobuf::io::ArrayOutputStream array_output(buffer, buffer_length);
		google::protobuf::io::CodedOutputStream coded_output(&array_output);

		coded_output.WriteLittleEndian32(message_length);
		message.SerializeToCodedStream(&coded_output);

		int sent_bytes = write(socket, buffer, buffer_length);
		if (sent_bytes != buffer_length) {
			return false;
		}
		return true;
	#endif
		google::protobuf::io::FileOutputStream		raw_out(_sockfd,0);
		google::protobuf::io::CodedOutputStream		coded_out(&raw_out);
		coded_out.WriteVarint32(message.ByteSize());
		message.SerializeToCodedStream(&coded_out);
	}

	bool
	Read(communication::MessageFromSlave& message)
	{
		google::protobuf::uint32	len;
#if (0)
		google::protobuf::uint8		prefix[sizeof(len)];
	
		if (sizeof(len) != read(_sockfd, prefix, sizeof(len)))
		{
			printf("ProxyDriverData::Read: Peer disconnected.");
			return false;
		}
		google::protobuf::io::CodedInputStream::ReadLittleEndian32FromArray(prefix, &len);
#else
		len = _read_raw_varint32(_sockfd);
#endif
	
		google::protobuf::uint8		buffer[len];
		if (len != read(_sockfd, buffer, len))
		{
			printf("ProxyDriverData::Read: Peer disconnected 2.");
			return false;
		}
		google::protobuf::io::ArrayInputStream buf_in(buffer, len);
		google::protobuf::io::CodedInputStream coded_in(&buf_in);
	
		if (message.ParseFromCodedStream(&coded_in))
		{
			return true;
		}
		else
		{
			printf("ProxyDriverData::Read: Error reading message contents.");
			return false;
		}
	}

	int
	NextQueryId()
	{
		++_prev_query_id;
		return _prev_query_id;
	}
private:
	unsigned int		_id;
	int			_sockfd;
	static unsigned int	_prev_id;
	static int		_prev_query_id;
}; // class ProxyDriverData

unsigned int ProxyDriverData::_prev_id = 0;
int ProxyDriverData::_prev_query_id = 0;

#define DRIVER_DATA (reinterpret_cast<ProxyDriverData*>(pnd->driver_data))

// ==================================================================
static size_t
proxydriver_scan(const nfc_context *context, nfc_connstring connstrings[], const size_t connstrings_len)
{
	printf("proxydriver_scan\n");
	sprintf(connstrings[0], "mdemu-driver:tcp:%s:%d", TARGET_HOSTNAME, TARGET_PORT);
	return 1; // there is just 1 emulator.
}

// ==================================================================
static nfc_device *
proxydriver_open(const nfc_context *context, const nfc_connstring connstring)
{
	int			part_count = 0;
	char*			stmp;
	char*			parts[4];
	int			sockfd = -1;
	struct sockaddr_in	server_addr;
	nfc_device*		pnd = NULL;

	printf("proxydriver_open: connect to: %s\n", connstring);

	// 1. Parse the connstring
	stmp = (char*)alloca(strlen(connstring));
	strcpy(stmp, connstring);

	parts[0] = stmp;
	while (part_count<4)
	{
		char*	pos = strchr(parts[part_count], ':');
		++part_count;
		if (pos == NULL)
		{
			break;
		}
		else
		{
			*pos = 0;
			parts[part_count] = pos + 1;
		}
	}

	if (part_count<4 || strcmp(parts[1], "tcp")!=0)
	{
		printf("proxydriver: Invalid connection string: %s\n", connstring);
		return NULL;
	}

	// 2. Connect!
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		printf("proxydriver: Socket create failed.\n");
		return NULL;
	}

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(TARGET_HOSTNAME);
	server_addr.sin_port = htons(TARGET_PORT);
	
	if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("proxydriver: Cannot connect to host %s port %d\n", TARGET_HOSTNAME, TARGET_PORT);
		return NULL;
	}

	printf("proxydriver: socket %d: Connected to the emulator!\n", sockfd);

	pnd = nfc_device_new(context, connstring);
	pnd->driver_data = new ProxyDriverData(sockfd);
	pnd->driver = &proxydriver_driver;

	printf("proxydriver: socket %d: Connected to the emulator 2!\n", sockfd);
	return pnd;
}

// ==================================================================
static void
proxydriver_close(nfc_device *pnd)
{
	printf("proxydriver_close: id:%d.\n", DRIVER_DATA->id());
	delete DRIVER_DATA;
	pnd->driver_data = NULL;
	nfc_device_free(pnd);
}

// ==================================================================
static const char *
proxydriver_strerror(const struct nfc_device *pnd)
{
	printf("proxydriver_strerror: NOT IMPLEMENTED.\n");
	return "Unknown error";
}

// ==================================================================
// The NFC device is configured to function as RFID reader.
static int
proxydriver_initiator_init(struct nfc_device *pnd)
{
	printf("proxydriver_initiator_init: id %d.\n", DRIVER_DATA->id());
	return 0;
}

// ==================================================================
static const uint8_t nfcid1[7] = { 0x04, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
static const uint8_t ats[5] = { 0x75, 0x77, 0x81, 0x02, 0x00 };

// ==================================================================
static void
_init_iso14443A(nfc_iso14443a_info* nai)
{
	printf("_init_iso14443A:\n");
	nai->abtAtqa[0] = 0x03;
	nai->abtAtqa[1] = 0x44;
	nai->btSak = 0x20;

	// Copy the NFCID1
	nai->szUidLen = sizeof(nfcid1);
	memcpy(nai->abtUid, nfcid1, sizeof(nfcid1));

	// Did we received an optional ATS (Smardcard ATR)
	nai->szAtsLen = 5;
	memcpy(nai->abtAts, ats, sizeof(ats));
}

// ==================================================================
static int
proxydriver_initiator_select_passive_target(struct nfc_device *pnd,
                                      const nfc_modulation nm,
                                      const uint8_t *pbtInitData, const size_t szInitData,
                                      nfc_target *pnt)
{
	printf("proxydriver_select_passive_target: id %d; modulation: %d;\n", DRIVER_DATA->id(), (int)nm.nmt);
	switch (nm.nmt)
	{
	case NMT_ISO14443A:
		printf("Iso1443A requested.\n");
		if (pnt)
		{
			_init_iso14443A(&pnt->nti.nai);
			pnt->nm = nm;
		}
		break;
	default:
		printf("Unknown nfc modulation: %d\n", (int)nm.nmt);
		pnd->last_error = NFC_ENOTIMPL;
		return pnd->last_error;
	}
	return 1;
}

// ==================================================================
static int
proxydriver_initiator_poll_target(struct nfc_device *pnd,
                            const nfc_modulation *pnmModulations, const size_t szModulations,
                            const uint8_t uiPollNr, const uint8_t uiPeriod,
                            nfc_target *pnt)
{
	printf("proxydriver_poll_target: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_initiator_select_dep_target(struct nfc_device *pnd,
                                  const nfc_dep_mode ndm, const nfc_baud_rate nbr,
                                  const nfc_dep_info *pndiInitiator,
                                  nfc_target *pnt,
                                  const int timeout)
{
	printf("proxydriver_select_dep_target: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_initiator_deselect_target(struct nfc_device *pnd)
{
	printf("proxydriver_deselect_target.\n");
	return 0;
}

// ==================================================================
static int
proxydriver_initiator_transceive_bytes(struct nfc_device *pnd, const uint8_t *pbtTx, const size_t szTx, uint8_t *pbtRx,
                                 const size_t szRx, int timeout)
{
	printf("proxydriver_transceive_bytes: id:%d.\n", DRIVER_DATA->id());
	printf("proxydriver_transceive_bytes: szTx=%lu bytes, szRx=%lu bytes.\n", szTx, szRx);

	try
	{
		// 1. Send the message.
		int				qid = DRIVER_DATA->NextQueryId();
		communication::MessageToSlave	query;
		query.set_id(qid);
		query.set_query((const char*)pbtTx, szTx);
		query.set_responselength(szRx);
		DRIVER_DATA->Write(query);

		// 2. Get the response.
		communication::MessageFromSlave	response;
		DRIVER_DATA->Read(response);
		if (response.has_id() && response.id()==qid)
		{
			if (response.has_response())
			{
				// must be ok.
				const std::string	s(response.response());
				memcpy(pbtRx, s.c_str(), s.size());
				memset(pbtRx + s.size(), 0, szRx - s.size());
				if (s.size() > szRx)
				{
					printf("proxydriver: Expected at most %lu bytes, got %lu bytes!\n", szRx, s.size());
				}
				return s.size();
			}
			else if (response.has_message())
			{
				printf("proxydriver: Error from the emulator: %s\n", "");
			}
			else
			{
				printf("proxydriver: Empty response for query id: %d.\n", qid);
			}
		}
		else
		{
			printf("proxydriver: Response Id mismatch.\n");
		}
	}
	catch (const std::exception& e)
	{
		printf("proxydriver_initiator_transceive_bytes: Error: %s\n", e.what());
	}
	return -1;
}

// ==================================================================
static int
proxydriver_initiator_transceive_bits(struct nfc_device *pnd, const uint8_t *pbtTx, const size_t szTxBits,
                                const uint8_t *pbtTxPar, uint8_t *pbtRx, uint8_t *pbtRxPar)
{
	printf("proxydriver_transceive_bits: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_initiator_transceive_bytes_timed(struct nfc_device *pnd, const uint8_t *pbtTx, const size_t szTx, uint8_t *pbtRx, const size_t szRx, uint32_t *cycles)
{
	printf("proxydriver_transceive_bytes_timed: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_initiator_transceive_bits_timed(struct nfc_device *pnd, const uint8_t *pbtTx, const size_t szTxBits,
                                      const uint8_t *pbtTxPar, uint8_t *pbtRx, uint8_t *pbtRxPar, uint32_t *cycles)
{
	printf("proxydriver_transceive_bits_timed: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_initiator_target_is_present(struct nfc_device *pnd, const nfc_target nt)
{
	printf("proxydriver_target_is_present: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_target_init(struct nfc_device *pnd, nfc_target *pnt, uint8_t *pbtRx, const size_t szRxLen, int timeout)
{
	printf("proxydriver_target_init: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_target_send_bytes(struct nfc_device *pnd, const uint8_t *pbtTx, const size_t szTx, int timeout)
{
	printf("proxydriver_target_send_bytes: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_target_receive_bytes(struct nfc_device *pnd, uint8_t *pbtRx, const size_t szRxLen, int timeout)
{
	printf("proxydriver_target_receive_bytes: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_target_send_bits(struct nfc_device *pnd, const uint8_t *pbtTx, const size_t szTxBits, const uint8_t *pbtTxPar)
{
	printf("proxydriver_target_send_bits: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_target_receive_bits(struct nfc_device *pnd, uint8_t *pbtRx, const size_t szRxLen, uint8_t *pbtRxPar)
{
	printf("proxydriver_target_receive_bits: NOT IMPLEMENTED.\n");
	return -1;
}

// not really used :)
// ==================================================================
static int
proxydriver_set_property_bool(struct nfc_device *pnd, const nfc_property property, const bool bEnable)
{
	printf("proxydriver_set_property_bool: %d %s: NOT IMPLEMENTED.\n", property, bEnable ? "true" : "false");
	return 0;
}

// ==================================================================
static int
proxydriver_set_property_int(struct nfc_device *pnd, const nfc_property property, const int value)
{
	printf("proxydriver_set_property_int: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_get_supported_modulation(nfc_device *pnd, const nfc_mode mode, const nfc_modulation_type * *const supported_mt)
{
	printf("proxydriver_get_supported_modulation: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_get_supported_baud_rate(nfc_device *pnd, const nfc_modulation_type nmt, const nfc_baud_rate * *const supported_br)
{
	printf("proxydriver_get_supported_baud_rate: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_get_information_about(nfc_device *pnd, char **pbuf)
{
	printf("proxydriver_get_information_about: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_abort_command(nfc_device *pnd)
{
	printf("proxydriver_abort_command: NOT IMPLEMENTED.\n");
	return -1;
}

// ==================================================================
static int
proxydriver_idle(struct nfc_device *pnd)
{
	printf("proxydriver_idle\n");
	return -1;
}

// ==================================================================
// ==================================================================
struct nfc_driver proxydriver_driver = { 0, (scan_type_enum)0, };

// ==================================================================
#if defined(__cplusplus)
extern "C" {
#endif
nfc_driver*
proxydriver_new(const char* host, const int port)
{
	nfc_driver*	r = &proxydriver_driver;

	r->name                             = "mdemu-driver";
	r->scan                             = proxydriver_scan;
	r->open                             = proxydriver_open;
	r->close                            = proxydriver_close;
	r->strerror                         = proxydriver_strerror;

	r->initiator_init                   = proxydriver_initiator_init;
	r->initiator_init_secure_element    = NULL; // No secure-element support
	r->initiator_select_passive_target  = proxydriver_initiator_select_passive_target;
	r->initiator_poll_target            = proxydriver_initiator_poll_target;
	r->initiator_select_dep_target      = proxydriver_initiator_select_dep_target;
	r->initiator_deselect_target        = proxydriver_initiator_deselect_target;
	r->initiator_transceive_bytes       = proxydriver_initiator_transceive_bytes;
	r->initiator_transceive_bits        = proxydriver_initiator_transceive_bits;
	r->initiator_transceive_bytes_timed = proxydriver_initiator_transceive_bytes_timed;
	r->initiator_transceive_bits_timed  = proxydriver_initiator_transceive_bits_timed;
	r->initiator_target_is_present      = proxydriver_initiator_target_is_present;

	r->target_init           = proxydriver_target_init;
	r->target_send_bytes     = proxydriver_target_send_bytes;
	r->target_receive_bytes  = proxydriver_target_receive_bytes;
	r->target_send_bits      = proxydriver_target_send_bits;
	r->target_receive_bits   = proxydriver_target_receive_bits;

	r->device_set_property_bool     = proxydriver_set_property_bool;
	r->device_set_property_int      = proxydriver_set_property_int;
	r->get_supported_modulation     = proxydriver_get_supported_modulation;
	r->get_supported_baud_rate      = proxydriver_get_supported_baud_rate;
	r->device_get_information_about = proxydriver_get_information_about;

	r->abort_command  = proxydriver_abort_command;
	r->idle           = proxydriver_idle;
	r->powerdown      = NULL; // no power down :)

	return r;
}

#if defined(__cplusplus)
}
#endif

