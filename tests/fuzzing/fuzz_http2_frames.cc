#include "proxy/http2/HTTP2.h"
#include "proxy/http2/Http2Frame.h"
#include "iocore/eventsystem/IOBuffer.h"
#include "records/RecordsConfig.h"
#include "tscore/Diags.h"
#include "tscore/Layout.h"
#include "tsutil/PostScript.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

extern int cmd_disable_pfreelist;

namespace
{
constexpr size_t MAX_INPUT_LENGTH = 64 * 1024;
constexpr size_t MAX_FRAMES       = 32;

IOVec
input_iovec(const uint8_t *data, size_t size)
{
  return {const_cast<uint8_t *>(data), size};
}

void
exercise_payload(const uint8_t *data, size_t size)
{
  std::array<uint8_t, 16> output{};
  IOVec                   input = input_iovec(data, size);

  if (size >= HTTP2_HEADERS_PADLEN_LEN) {
    Http2HeadersParameter parameter;

    http2_parse_headers_parameter(input, parameter);
  }
  if (size >= HTTP2_PRIORITY_LEN) {
    Http2Priority priority;

    http2_parse_priority_parameter(input, priority);
  }
  if (size >= HTTP2_RST_STREAM_LEN) {
    Http2RstStream reset{};
    uint32_t       window = 0;

    http2_parse_rst_stream(input, reset);
    http2_write_rst_stream(reset.error_code, make_iovec(output.data(), output.size()));
    http2_parse_window_update(input, window);
    http2_write_window_update(window, make_iovec(output.data(), output.size()));
  }
  for (size_t offset = 0, count = 0; offset + HTTP2_SETTINGS_PARAMETER_LEN <= size && count < MAX_FRAMES;
       offset += HTTP2_SETTINGS_PARAMETER_LEN, ++count) {
    Http2SettingsParameter parameter{};

    http2_parse_settings_parameter(input_iovec(data + offset, size - offset), parameter);
    http2_settings_parameter_is_valid(parameter);
    http2_write_settings(parameter, make_iovec(output.data(), output.size()));
    http2_write_settings(parameter, make_iovec(output.data(), count % HTTP2_SETTINGS_PARAMETER_LEN));
  }
  if (size >= HTTP2_GOAWAY_LEN) {
    Http2Goaway goaway;

    http2_parse_goaway(input, goaway);
    http2_write_goaway(goaway, make_iovec(output.data(), output.size()));
    http2_write_goaway(goaway, make_iovec(output.data(), HTTP2_GOAWAY_LEN - 1));
    http2_write_ping(data, make_iovec(output.data(), output.size()));
    http2_write_ping(data, make_iovec(output.data(), HTTP2_PING_LEN - 1));
  }

  Http2SettingsParameter parameter{};
  http2_parse_settings_parameter(input_iovec(data, std::min(size, HTTP2_SETTINGS_PARAMETER_LEN - 1)), parameter);
}

void
serialize_frame(const Http2FrameHeader &header, const uint8_t *data, size_t size)
{
  MIOBuffer           *output = new_MIOBuffer(BUFFER_SIZE_INDEX_4K);
  IOBufferReader      *reader = output->alloc_reader();
  ts::PostScript       cleanup([&]() { free_MIOBuffer(output); });
  std::vector<uint8_t> payload(data, data + size);
  uint32_t             length = static_cast<uint32_t>(payload.size());

  switch (header.type) {
  case HTTP2_FRAME_TYPE_DATA: {
    MIOBuffer      *source = new_MIOBuffer(BUFFER_SIZE_INDEX_128);
    ts::PostScript  source_cleanup([&]() { free_MIOBuffer(source); });
    IOBufferReader *source_reader = source->alloc_reader();

    source->write(data, size);
    Http2DataFrame frame(header.streamid, header.flags, source_reader, length);
    frame.write_to(output);
    break;
  }
  case HTTP2_FRAME_TYPE_HEADERS: {
    Http2HeadersFrame frame(header.streamid, header.flags, payload.data(), length);

    frame.write_to(output);
    break;
  }
  case HTTP2_FRAME_TYPE_RST_STREAM: {
    if (size >= HTTP2_RST_STREAM_LEN) {
      Http2RstStream reset{};

      http2_parse_rst_stream(input_iovec(data, size), reset);
      Http2RstStreamFrame frame(header.streamid, reset.error_code);
      frame.write_to(output);
    }
    break;
  }
  case HTTP2_FRAME_TYPE_SETTINGS: {
    std::vector<Http2SettingsParameter> parameters;

    for (size_t offset  = 0; offset + HTTP2_SETTINGS_PARAMETER_LEN <= size && parameters.size() < MAX_FRAMES;
         offset        += HTTP2_SETTINGS_PARAMETER_LEN) {
      Http2SettingsParameter parameter{};

      http2_parse_settings_parameter(input_iovec(data + offset, size - offset), parameter);
      parameters.push_back(parameter);
    }
    Http2SettingsFrame frame(header.streamid, header.flags, parameters.data(), static_cast<uint32_t>(parameters.size()));
    frame.write_to(output);
    break;
  }
  case HTTP2_FRAME_TYPE_PUSH_PROMISE: {
    Http2PushPromise promise;

    promise.promised_streamid = header.streamid;
    Http2PushPromiseFrame frame(header.streamid, header.flags, promise, payload.data(), length);
    frame.write_to(output);
    break;
  }
  case HTTP2_FRAME_TYPE_PING: {
    if (size >= HTTP2_PING_LEN) {
      Http2PingFrame frame(header.streamid, header.flags, data);

      frame.write_to(output);
    }
    break;
  }
  case HTTP2_FRAME_TYPE_GOAWAY: {
    if (size >= HTTP2_GOAWAY_LEN) {
      Http2Goaway goaway;

      http2_parse_goaway(input_iovec(data, size), goaway);
      Http2GoawayFrame frame(goaway);
      frame.write_to(output);
    }
    break;
  }
  case HTTP2_FRAME_TYPE_WINDOW_UPDATE: {
    if (size >= HTTP2_WINDOW_UPDATE_LEN) {
      uint32_t window = 0;

      http2_parse_window_update(input_iovec(data, size), window);
      Http2WindowUpdateFrame frame(header.streamid, window);
      frame.write_to(output);
    }
    break;
  }
  case HTTP2_FRAME_TYPE_CONTINUATION: {
    Http2ContinuationFrame frame(header.streamid, header.flags, payload.data(), length);

    frame.write_to(output);
    break;
  }
  default:
    break;
  }

  if (reader->read_avail() >= static_cast<int64_t>(HTTP2_FRAME_HEADER_LEN)) {
    std::array<uint8_t, HTTP2_FRAME_HEADER_LEN> bytes{};
    Http2FrameHeader                            parsed{};

    reader->read(bytes.data(), bytes.size());
    http2_parse_frame_header(make_iovec(bytes.data(), bytes.size()), parsed);
    http2_frame_header_is_valid(parsed, HTTP2_MAX_FRAME_SIZE);
  }
}
} // namespace

extern "C" int
LLVMFuzzerInitialize(int *, char ***)
{
  cmd_disable_pfreelist = true;
  Layout::create();
  DiagsPtr::set(new Diags("fuzzing", "", "", nullptr));
  RecProcessInit();
  LibRecordsConfigInit();
  ink_event_system_init(EVENT_SYSTEM_MODULE_PUBLIC_VERSION);
  static EThread main_thread;
  main_thread.set_specific();
  Http2::max_frame_size                = HTTP2_MAX_FRAME_SIZE;
  Http2::write_buffer_block_size_index = BUFFER_SIZE_INDEX_4K;
  return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > MAX_INPUT_LENGTH) {
    return 0;
  }

  exercise_payload(data, size);
  for (size_t offset = 0, count = 0; count < MAX_FRAMES && offset < size; ++count) {
    Http2FrameHeader                            header{};
    std::array<uint8_t, HTTP2_FRAME_HEADER_LEN> output{};

    if (!http2_parse_frame_header(input_iovec(data + offset, size - offset), header)) {
      break;
    }
    http2_frame_header_is_valid(header, HTTP2_MAX_FRAME_SIZE);
    http2_write_frame_header(header, make_iovec(output.data(), output.size()));
    http2_write_frame_header(header, make_iovec(output.data(), header.flags % HTTP2_FRAME_HEADER_LEN));
    offset                += HTTP2_FRAME_HEADER_LEN;
    size_t payload_length  = std::min(static_cast<size_t>(header.length), size - offset);

    exercise_payload(data + offset, payload_length);
    serialize_frame(header, data + offset, payload_length);
    offset += payload_length;
  }
  return 0;
}
