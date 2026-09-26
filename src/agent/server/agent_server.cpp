#if defined(C_DEBUG) && defined(C_DOSBOX_AGENT)
#include "agent/agent_server.h"

#include "agent/agent_bridge.h"
#include "agent/debugger_adapter.h"
#include "agent/debugger_output_parser.h"
#include "agent/io_adapter.h"
#include "agent/trace_store.h"
#include "debug_re.h"
#include "inspector.h"
#include "../transport/rpc_transport.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <condition_variable>
#include <deque>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <utility>
#include <vector>
#include <thread>

#ifdef WIN32
#include <windows.h>
#else
#include <limits.h>
#include <unistd.h>
#endif

namespace dosbox_agent {
namespace {

static const int kErrorSessionBusy = -32001;
static const int kErrorSessionNotFound = -32002;
static const int kErrorTargetRunning = -32003;
static const int kErrorCapabilityUnavailable = -32004;
static const int kErrorRequestTooLarge = -32009;
static const int kErrorRequestIdConflict = -32010;
static const int kErrorOperationTimeout = -32011;
static const int kErrorInvalidBinaryLength = -32012;
static const int kErrorMemoryPreconditionFailed = -32013;
static const int kErrorAddressNotMapped = -32014;
static const int kErrorBreakpointNotFound = -32015;
static const int kErrorCommandRejected = -32016;
static const int kErrorCursorExpired = -32017;
static const std::size_t kOutputRingCapacity = 1024;
static const std::size_t kCompletedResponseCacheByteLimit = 8u * 1024u * 1024u;

static JsonValue Object()
{
    return JsonValue::Object();
}

static void Add(JsonValue* object, const char* name, const JsonValue& value)
{
    object->object[name] = value;
}

static JsonValue String(const std::string& value)
{
    return JsonValue::String(value);
}

static JsonValue Number(const std::uint64_t value)
{
    return JsonValue::Number(std::to_string(value));
}

static bool GetString(const JsonValue& object, const char* name, std::string* value)
{
    const JsonValue* field = object.Find(name);
    if (field == NULL || field->type != JsonType::String)
        return false;
    *value = field->text;
    return true;
}

static bool GetBool(const JsonValue& object, const char* name, bool* value)
{
    const JsonValue* field = object.Find(name);
    if (field == NULL || field->type != JsonType::Bool)
        return false;
    *value = field->boolean;
    return true;
}

static bool GetUnsignedInteger(const JsonValue& value, std::uint32_t* result)
{
    if (value.type != JsonType::Number || value.text.empty())
        return false;

    std::uint64_t parsed = 0;
    for (std::string::const_iterator it = value.text.begin(); it != value.text.end(); ++it) {
        if (!std::isdigit(static_cast<unsigned char>(*it)))
            return false;
        parsed = parsed * 10 + static_cast<unsigned int>(*it - '0');
        if (parsed > (std::numeric_limits<std::uint32_t>::max)())
            return false;
    }

    *result = static_cast<std::uint32_t>(parsed);
    return true;
}

static bool ParseCursor(const JsonValue* value,
                        const char* prefix,
                        bool* has_cursor,
                        std::uint64_t* cursor)
{
    if (value == NULL || value->type == JsonType::Null) {
        *has_cursor = false;
        *cursor = 0;
        return true;
    }
    if (value->type != JsonType::String)
        return false;
    const std::string expected_prefix = std::string(prefix) + "-";
    if (value->text.compare(0, expected_prefix.size(), expected_prefix) != 0 ||
        value->text.size() == expected_prefix.size())
        return false;
    std::uint64_t parsed = 0;
    for (std::size_t index = expected_prefix.size(); index < value->text.size(); ++index) {
        const char character = value->text[index];
        if (!std::isdigit(static_cast<unsigned char>(character)))
            return false;
        const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
        if (parsed > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10u)
            return false;
        parsed = parsed * 10u + digit;
    }
    *has_cursor = true;
    *cursor = parsed;
    return true;
}

static std::string FormatCursor(const char* prefix, const std::uint64_t sequence)
{
    return std::string(prefix) + "-" + std::to_string(sequence);
}

static std::uint64_t TimestampMilliseconds()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

static bool ParseFixedWidthHex(const JsonValue& value,
                               const std::size_t width,
                               std::uint32_t* result)
{
    if (value.type != JsonType::String || value.text.size() != width + 2 ||
        value.text[0] != '0' || value.text[1] != 'x')
        return false;

    std::uint32_t parsed = 0;
    for (std::size_t index = 2; index < value.text.size(); ++index) {
        const char character = value.text[index];
        unsigned int digit = 0;
        if (character >= '0' && character <= '9') digit = static_cast<unsigned int>(character - '0');
        else if (character >= 'A' && character <= 'F') digit = static_cast<unsigned int>(character - 'A' + 10);
        else if (character >= 'a' && character <= 'f') digit = static_cast<unsigned int>(character - 'a' + 10);
        else return false;
        parsed = (parsed << 4u) | digit;
    }
    *result = parsed;
    return true;
}

static const char* MemorySpaceName(const MemorySpace space)
{
    switch (space) {
    case MemorySpace::Segmented: return "segmented";
    case MemorySpace::Linear: return "linear";
    case MemorySpace::Physical: return "physical";
    }
    return "unknown";
}

static bool ParseMemoryAddress(const JsonValue& params,
                               const char* method,
                               MemoryAddress* address,
                               std::string* error)
{
    const JsonValue* encoded = params.Find("address");
    if (encoded == NULL || encoded->type != JsonType::Object) {
        *error = std::string(method) + " requires address as an object";
        return false;
    }
    const JsonValue* space = encoded->Find("space");
    const JsonValue* segment = encoded->Find("segment");
    const JsonValue* offset = encoded->Find("offset");
    std::uint32_t parsed_segment = 0;
    if (space == NULL || space->type != JsonType::String || offset == NULL ||
        !ParseFixedWidthHex(*offset, 8, &address->offset)) {
        *error = std::string(method) + " requires address.offset as 0xNNNNNNNN";
        return false;
    }
    if (space->text == "segmented") {
        if (segment == NULL || !ParseFixedWidthHex(*segment, 4, &parsed_segment)) {
            *error = std::string(method) + " requires segmented address.segment as 0xNNNN";
            return false;
        }
        address->space = MemorySpace::Segmented;
        address->segment = static_cast<std::uint16_t>(parsed_segment);
    } else if (space->text == "linear") {
        address->space = MemorySpace::Linear;
        address->segment = 0;
    } else if (space->text == "physical") {
        address->space = MemorySpace::Physical;
        address->segment = 0;
    } else {
        *error = std::string(method) + " requires address.space segmented, linear, or physical";
        return false;
    }
    return true;
}

static JsonValue EncodeMemoryAddress(const MemoryAddress& address)
{
    JsonValue encoded = Object();
    Add(&encoded, "space", String(MemorySpaceName(address.space)));
    std::ostringstream offset;
    offset << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << address.offset;
    Add(&encoded, "offset", String(offset.str()));
    if (address.space == MemorySpace::Segmented) {
        std::ostringstream segment;
        segment << "0x" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << address.segment;
        Add(&encoded, "segment", String(segment.str()));
    }
    return encoded;
}

static std::string EncodeBase64(const std::vector<std::uint8_t>& data)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((data.size() + 2) / 3) * 4);
    for (std::size_t index = 0; index < data.size(); index += 3) {
        const std::uint32_t first = data[index];
        const std::uint32_t second = index + 1 < data.size() ? data[index + 1] : 0;
        const std::uint32_t third = index + 2 < data.size() ? data[index + 2] : 0;
        const std::uint32_t block = (first << 16u) | (second << 8u) | third;
        encoded.push_back(alphabet[(block >> 18u) & 0x3fu]);
        encoded.push_back(alphabet[(block >> 12u) & 0x3fu]);
        encoded.push_back(index + 1 < data.size() ? alphabet[(block >> 6u) & 0x3fu] : '=');
        encoded.push_back(index + 2 < data.size() ? alphabet[block & 0x3fu] : '=');
    }
    return encoded;
}

static bool DecodeBase64(const std::string& encoded, std::vector<std::uint8_t>* decoded)
{
    if (encoded.empty() || encoded.size() % 4 != 0)
        return false;

    decoded->clear();
    decoded->reserve((encoded.size() / 4) * 3);
    for (std::size_t index = 0; index < encoded.size(); index += 4) {
        unsigned int values[4] = {0, 0, 0, 0};
        unsigned int padding = 0;
        for (std::size_t offset = 0; offset < 4; ++offset) {
            const char character = encoded[index + offset];
            if (character == '=') {
                if (offset < 2 || index + 4 != encoded.size())
                    return false;
                ++padding;
                continue;
            }
            if (padding != 0)
                return false;
            if (character >= 'A' && character <= 'Z') values[offset] = static_cast<unsigned int>(character - 'A');
            else if (character >= 'a' && character <= 'z') values[offset] = static_cast<unsigned int>(character - 'a' + 26);
            else if (character >= '0' && character <= '9') values[offset] = static_cast<unsigned int>(character - '0' + 52);
            else if (character == '+') values[offset] = 62;
            else if (character == '/') values[offset] = 63;
            else return false;
        }
        if (padding > 2 || (padding == 1 && encoded[index + 3] != '=') ||
            (padding == 2 && (encoded[index + 2] != '=' || encoded[index + 3] != '=')))
            return false;
        const std::uint32_t block = (values[0] << 18u) | (values[1] << 12u) |
                                    (values[2] << 6u) | values[3];
        decoded->push_back(static_cast<std::uint8_t>((block >> 16u) & 0xffu));
        if (padding < 2)
            decoded->push_back(static_cast<std::uint8_t>((block >> 8u) & 0xffu));
        if (padding == 0)
            decoded->push_back(static_cast<std::uint8_t>(block & 0xffu));
    }
    return true;
}

static std::uint32_t RotateRight(const std::uint32_t value, const unsigned int amount)
{
    return (value >> amount) | (value << (32u - amount));
}

static std::string Sha256Hex(const std::vector<std::uint8_t>& data)
{
    static const std::uint32_t constants[] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };
    std::vector<std::uint8_t> padded(data);
    padded.push_back(0x80u);
    while ((padded.size() % 64) != 56)
        padded.push_back(0);
    const std::uint64_t bit_length = static_cast<std::uint64_t>(data.size()) * 8u;
    for (int shift = 56; shift >= 0; shift -= 8)
        padded.push_back(static_cast<std::uint8_t>((bit_length >> shift) & 0xffu));

    std::uint32_t state[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                              0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    for (std::size_t block_offset = 0; block_offset < padded.size(); block_offset += 64) {
        std::uint32_t words[64];
        for (std::size_t index = 0; index < 16; ++index) {
            const std::size_t offset = block_offset + index * 4;
            words[index] = (static_cast<std::uint32_t>(padded[offset]) << 24u) |
                           (static_cast<std::uint32_t>(padded[offset + 1]) << 16u) |
                           (static_cast<std::uint32_t>(padded[offset + 2]) << 8u) |
                           static_cast<std::uint32_t>(padded[offset + 3]);
        }
        for (std::size_t index = 16; index < 64; ++index) {
            const std::uint32_t s0 = RotateRight(words[index - 15], 7) ^ RotateRight(words[index - 15], 18) ^ (words[index - 15] >> 3u);
            const std::uint32_t s1 = RotateRight(words[index - 2], 17) ^ RotateRight(words[index - 2], 19) ^ (words[index - 2] >> 10u);
            words[index] = words[index - 16] + s0 + words[index - 7] + s1;
        }
        std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (std::size_t index = 0; index < 64; ++index) {
            const std::uint32_t s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
            const std::uint32_t choose = (e & f) ^ ((~e) & g);
            const std::uint32_t temporary1 = h + s1 + choose + constants[index] + words[index];
            const std::uint32_t s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
            const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temporary2 = s0 + majority;
            h = g; g = f; f = e; e = d + temporary1;
            d = c; c = b; b = a; a = temporary1 + temporary2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    std::ostringstream output;
    output << std::hex << std::nouppercase << std::setfill('0');
    for (std::size_t index = 0; index < 8; ++index)
        output << std::setw(8) << state[index];
    return output.str();
}

static bool NormalizeSha256(const std::string& value, std::string* normalized)
{
    if (value.size() != 64)
        return false;
    normalized->clear();
    normalized->reserve(value.size());
    for (std::string::const_iterator it = value.begin(); it != value.end(); ++it) {
        if (!std::isxdigit(static_cast<unsigned char>(*it)))
            return false;
        normalized->push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(*it))));
    }
    return true;
}

static bool IsAbsolutePath(const std::string& path)
{
#ifdef WIN32
    return (path.size() >= 3 && std::isalpha(static_cast<unsigned char>(path[0])) &&
            path[1] == ':' && (path[2] == '\\' || path[2] == '/')) ||
           (path.size() >= 2 && path[0] == '\\' && path[1] == '\\');
#else
    return !path.empty() && path[0] == '/';
#endif
}

static bool NormalizePathForComparison(const std::string& path,
                                       const std::string& base_directory,
                                       std::string* normalized)
{
    std::string resolved_path = path;
    if (!IsAbsolutePath(path) && !base_directory.empty()) {
        resolved_path = base_directory;
        if (resolved_path[resolved_path.size() - 1] != '\\' &&
            resolved_path[resolved_path.size() - 1] != '/')
            resolved_path += '/';
        resolved_path += path;
    }

#ifdef WIN32
    const DWORD required = GetFullPathNameA(resolved_path.c_str(), 0, NULL, NULL);
    if (required == 0)
        return false;
    std::vector<char> buffer(required, '\0');
    if (GetFullPathNameA(resolved_path.c_str(), required, &buffer[0], NULL) == 0)
        return false;
    normalized->assign(&buffer[0]);
#else
    char buffer[PATH_MAX];
    if (realpath(resolved_path.c_str(), buffer) == NULL)
        return false;
    normalized->assign(buffer);
#endif

    for (std::string::iterator it = normalized->begin(); it != normalized->end(); ++it) {
        if (*it == '\\')
            *it = '/';
#ifdef WIN32
        *it = static_cast<char>(std::tolower(static_cast<unsigned char>(*it)));
#endif
    }
    while (normalized->size() > 1 && normalized->back() == '/')
        normalized->pop_back();
    return true;
}

static std::string Error(const JsonValue& id,
                         const int code,
                         const std::string& message,
                         const std::string& reason)
{
    JsonValue data = Object();
    Add(&data, "reason", String(reason));
    return AGENT_MakeJsonRpcError(id, code, message, &data);
}

static std::string InvalidParams(const JsonValue& id, const std::string& message)
{
    return AGENT_MakeJsonRpcError(id, -32602, message);
}

static bool IsKnownMethod(const std::string& method)
{
    return method == "agent.capabilities" ||
           method == "session.start" ||
           method == "session.status" ||
           method == "session.stop" ||
           method == "execution.continue" ||
           method == "execution.pause" ||
           method == "execution.step" ||
           method == "execution.wait" ||
           method == "state.get_registers" ||
           method == "memory.read" ||
           method == "memory.write" ||
           method == "breakpoints.create" ||
           method == "breakpoints.list" ||
           method == "breakpoints.delete" ||
           method == "debug.output.read" ||
           method == "debugger.execute_command" ||
           method == "trace.start" ||
           method == "trace.read" ||
           method == "trace.stop" ||
           method == "session.attach" ||
           method == "input.key" ||
           method == "input.keys" ||
           method == "input.type_text" ||
           method == "input.mouse" ||
           method == "input.clear" ||
           method == "input.status" ||
           method == "screen.capture" ||
           method == "screen.read_text" ||
           method == "machine.status" ||
           method == "machine.set_speed" ||
           method == "state.save" ||
           method == "state.load" ||
           method == "mapper.trigger" ||
           method == "memory.peek" ||
           method == "memory.poke" ||
           method == "memory.scratch" ||
           method == "video.info" ||
           method == "debug.disassemble" ||
           method == "debug.stack" ||
           method == "state.set_registers" ||
           method == "calltrace.start" ||
           method == "calltrace.read" ||
           method == "calltrace.stop" ||
           method == "doslog.start" ||
           method == "doslog.read" ||
           method == "doslog.stop";
}

// Guest I/O methods work without a debugger session: they only need the emulation thread.
static bool IsIoMethod(const std::string& method)
{
    return method.compare(0, 6, "input.") == 0 ||
           method.compare(0, 7, "screen.") == 0 ||
           method.compare(0, 8, "machine.") == 0 ||
           method == "state.save" ||
           method == "state.load" ||
           method == "mapper.trigger" ||
           method == "memory.peek" ||
           method == "memory.poke" ||
           method == "memory.scratch" ||
           method.compare(0, 6, "video.") == 0 ||
           method.compare(0, 10, "calltrace.") == 0 ||
           method.compare(0, 7, "doslog.") == 0 ||
           method == "debug.disassemble" ||
           method == "debug.stack" ||
           method == "state.set_registers";
}

} // namespace

class AgentServer::Impl {
public:
    enum class SessionState {
        Starting,
        Stopped,
        Running,
        Exited,
        Failed
    };

    struct Operation {
        std::string id;
        SessionState terminal_state = SessionState::Running;
        std::string stop_kind;
        bool complete = false;
    };

    struct CachedResponse {
        std::string id_key;
        std::string fingerprint;
        std::string response;
        std::size_t bytes = 0;
    };

    struct DeferredRequest {
        JsonRpcRequest request;
        std::string fingerprint;
        std::function<bool(std::uint32_t)> wait;
        std::function<std::string()> finish;
    };

    struct MemoryWriteOperation {
        std::mutex mutex;
        std::condition_variable completed;
        bool done = false;
        bool precondition_failed = false;
        bool success = false;
        std::string error;
        MemoryAccessError access_error;
        std::vector<std::uint8_t> before;
        std::vector<std::uint8_t> after;
    };

    struct AdapterOperation {
        std::mutex mutex;
        std::condition_variable completed;
        bool done = false;
        bool success = false;
        bool continued = false;
        std::string error;
        MemoryAccessError access_error;
        RegisterSnapshot registers;
        std::vector<std::uint8_t> data;
        NativeBreakpoint breakpoint;
        std::string raw_output;
        std::vector<TraceSample> trace_samples;
        bool trace_active = false;
        std::size_t trace_event_count = 0;
    };

    struct StepOperation {
        std::shared_ptr<AdapterOperation> dispatch;
        std::shared_ptr<AdapterOperation> registers;
        std::mutex mutex;
        bool registers_submitted = false;
    };

    struct OutputRecord {
        std::uint64_t sequence = 0;
        std::uint64_t timestamp = 0;
        std::string level;
        std::string source;
        std::string message;
    };

    struct Breakpoint {
        std::string id;
        NativeBreakpoint native;
        bool enabled = true;
    };

    struct Session {
        std::string id;
        std::string target_command;
        bool attached = false; // session.attach: bound to the running machine, nothing was launched
        SessionState state = SessionState::Starting;
        std::string last_stop_kind;
        std::uint16_t last_stop_segment = 0;
        std::uint32_t last_stop_instruction_pointer = 0;
        std::string last_stop_breakpoint_id;
        MemoryAddress last_stop_breakpoint_address;
        bool has_last_stop_breakpoint_address = false;
        std::string failure_message;
        std::uint64_t state_revision = 0;
        std::uint64_t next_operation = 1;
        std::uint64_t next_breakpoint = 1;
        std::uint64_t next_output_sequence = 1;
        std::string pending_stop_kind;
        std::string startup_phase;
        std::uint64_t startup_entry_breakpoint_baseline = 0;
        std::chrono::steady_clock::time_point startup_deadline;
        std::chrono::steady_clock::time_point termination_deadline;
        std::uint32_t startup_retry_count = 0;
        std::uint32_t termination_retry_count = 0;
        bool startup_entry_breakpoint_created = false;
        std::map<std::string, Operation> operations;
        std::map<std::string, Breakpoint> breakpoints;
        std::deque<OutputRecord> output;
        TraceStore trace;
        std::deque<CachedResponse> completed_requests;
        std::size_t completed_response_bytes = 0;
        std::map<std::string, DeferredRequest> deferred_requests;
    };

    AgentConfig config;
    std::unique_ptr<IRpcTransport> transport;
    std::unique_ptr<Session> session;
    std::mutex mutex;
    std::condition_variable state_changed;
    std::condition_variable lifecycle_changed;
    std::uint64_t next_session = 1;
    std::size_t active_requests = 0;
    std::size_t active_emulation_callbacks = 0;
    bool started = false;
    bool stopping = false;
    std::shared_ptr<class AgentRuntime> runtime;
    std::atomic<std::uint64_t> lifecycle_generation{0};
    std::string request_path_base;
};

class AgentRuntime {
public:
    typedef EmulationThreadQueue::Command Command;

    virtual ~AgentRuntime() {}
    virtual bool RequireAvailable(std::string* error) const = 0;
    virtual std::uint64_t Submit(Command command) = 0;
    virtual std::uint64_t SubmitAfter(std::uint32_t delay_ms, Command command) = 0;
    virtual bool IsReadyForTargetStart() const = 0;
    virtual std::uint64_t EntryBreakpointSequence() const = 0;
    virtual bool Continue(std::string* error) const = 0;
    virtual bool Pause(std::string* error) const = 0;
    virtual bool StartTargetAtEntry(const std::string& command,
                                    const std::vector<std::string>& arguments,
                                    const std::string& workdir,
                                    std::string* error) const = 0;
    virtual bool GetRegisters(RegisterSnapshot* registers, std::string* error) const = 0;
    virtual bool Step(StepMode mode, bool* continued, std::string* error) const = 0;
    virtual bool ReadMemory(const MemoryAddress& address,
                            std::size_t length,
                            std::vector<std::uint8_t>* data,
                            MemoryAccessError* access_error,
                            std::string* error) const = 0;
    virtual bool WriteMemory(const MemoryAddress& address,
                             const std::vector<std::uint8_t>& data,
                             std::vector<std::uint8_t>* after,
                             MemoryAccessError* access_error,
                             std::string* error) const = 0;
    virtual bool CreateBreakpoint(BreakpointKind kind,
                                  const MemoryAddress& address,
                                  bool once,
                                  NativeBreakpoint* breakpoint,
                                  MemoryAccessError* access_error,
                                  std::string* error) const = 0;
    virtual bool DeleteBreakpoint(const NativeBreakpoint& breakpoint, std::string* error) const = 0;
    virtual std::uintptr_t ConsumeLastBreakpointHandle() const = 0;
    virtual bool ExecuteDiagnosticCommand(const std::string& command,
                                          std::string* raw_output,
                                          std::string* error) const = 0;
    virtual bool StartTrace(const std::string& detail, std::uint32_t instruction_count, std::string* error) const = 0;
    virtual bool ReadTrace(std::vector<TraceSample>* samples, bool* active, std::string* error) const = 0;
    virtual bool StopTrace(std::size_t* event_count, std::string* error) const = 0;
    virtual bool TerminateTarget(std::string* error) const = 0;
    virtual IoBackend& Io() = 0;
};

class ProductionAgentRuntime final : public AgentRuntime {
public:
    IoBackend& Io() override { return *io; }

    bool RequireAvailable(std::string* error) const override
    {
        DebuggerAdapter adapter;
        return adapter.RequireAvailable(error);
    }

    std::uint64_t Submit(Command command) override
    {
        return AGENT_EmulationQueue().Submit(std::move(command));
    }

    std::uint64_t SubmitAfter(const std::uint32_t delay_ms, Command command) override
    {
        return AGENT_EmulationQueue().SubmitAfter(delay_ms, std::move(command));
    }

#define AGENT_RUNTIME_FORWARD(method, signature, args) \
    signature override { DebuggerAdapter adapter; return adapter.method args; }
    AGENT_RUNTIME_FORWARD(IsReadyForTargetStart, bool IsReadyForTargetStart() const, ())
    AGENT_RUNTIME_FORWARD(EntryBreakpointSequence, std::uint64_t EntryBreakpointSequence() const, ())
    AGENT_RUNTIME_FORWARD(Continue, bool Continue(std::string* error) const, (error))
    AGENT_RUNTIME_FORWARD(Pause, bool Pause(std::string* error) const, (error))
    AGENT_RUNTIME_FORWARD(StartTargetAtEntry, bool StartTargetAtEntry(const std::string& command, const std::vector<std::string>& arguments, const std::string& workdir, std::string* error) const, (command, arguments, workdir, error))
    AGENT_RUNTIME_FORWARD(GetRegisters, bool GetRegisters(RegisterSnapshot* registers, std::string* error) const, (registers, error))
    AGENT_RUNTIME_FORWARD(Step, bool Step(StepMode mode, bool* continued, std::string* error) const, (mode, continued, error))
    AGENT_RUNTIME_FORWARD(ReadMemory, bool ReadMemory(const MemoryAddress& address, std::size_t length, std::vector<std::uint8_t>* data, MemoryAccessError* access_error, std::string* error) const, (address, length, data, access_error, error))
    AGENT_RUNTIME_FORWARD(WriteMemory, bool WriteMemory(const MemoryAddress& address, const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>* after, MemoryAccessError* access_error, std::string* error) const, (address, data, after, access_error, error))
    AGENT_RUNTIME_FORWARD(CreateBreakpoint, bool CreateBreakpoint(BreakpointKind kind, const MemoryAddress& address, bool once, NativeBreakpoint* breakpoint, MemoryAccessError* access_error, std::string* error) const, (kind, address, once, breakpoint, access_error, error))
    AGENT_RUNTIME_FORWARD(DeleteBreakpoint, bool DeleteBreakpoint(const NativeBreakpoint& breakpoint, std::string* error) const, (breakpoint, error))
    AGENT_RUNTIME_FORWARD(ConsumeLastBreakpointHandle, std::uintptr_t ConsumeLastBreakpointHandle() const, ())
    AGENT_RUNTIME_FORWARD(ExecuteDiagnosticCommand, bool ExecuteDiagnosticCommand(const std::string& command, std::string* raw_output, std::string* error) const, (command, raw_output, error))
    AGENT_RUNTIME_FORWARD(StartTrace, bool StartTrace(const std::string& detail, std::uint32_t instruction_count, std::string* error) const, (detail, instruction_count, error))
    AGENT_RUNTIME_FORWARD(ReadTrace, bool ReadTrace(std::vector<TraceSample>* samples, bool* active, std::string* error) const, (samples, active, error))
    AGENT_RUNTIME_FORWARD(StopTrace, bool StopTrace(std::size_t* event_count, std::string* error) const, (event_count, error))
    AGENT_RUNTIME_FORWARD(TerminateTarget, bool TerminateTarget(std::string* error) const, (error))
#undef AGENT_RUNTIME_FORWARD

private:
    std::unique_ptr<IoBackend> io = AGENT_CreateProductionIoBackend();
};

class FakeAgentRuntime final : public AgentRuntime {
public:
    bool RequireAvailable(std::string*) const override { return true; }

    std::uint64_t Submit(Command command) override
    {
        return Launch(0, std::move(command));
    }

    std::uint64_t SubmitAfter(const std::uint32_t delay_ms, Command command) override
    {
        return Launch(delay_ms, std::move(command));
    }

    bool IsReadyForTargetStart() const override { return true; }
    std::uint64_t EntryBreakpointSequence() const override { return 0; }

    bool Continue(std::string*) const override { return true; }

    bool Pause(std::string*) const override
    {
        AGENT_NotifyDebuggerStopped(0, 0x100);
        return true;
    }

    bool StartTargetAtEntry(const std::string&,
                            const std::vector<std::string>&,
                            const std::string&,
                            std::string*) const override
    {
        AGENT_NotifyDebuggerStopped(0, 0x100);
        return true;
    }

    bool TerminateTarget(std::string*) const override { return true; }

    IoBackend& Io() override { return *io; }

#define AGENT_RUNTIME_UNAVAILABLE(method, signature) \
    signature override { SetUnavailable(error); return false; }
    AGENT_RUNTIME_UNAVAILABLE(GetRegisters, bool GetRegisters(RegisterSnapshot*, std::string* error) const)
    AGENT_RUNTIME_UNAVAILABLE(Step, bool Step(StepMode, bool*, std::string* error) const)
    AGENT_RUNTIME_UNAVAILABLE(ReadMemory, bool ReadMemory(const MemoryAddress&, std::size_t, std::vector<std::uint8_t>*, MemoryAccessError*, std::string* error) const)
    AGENT_RUNTIME_UNAVAILABLE(WriteMemory, bool WriteMemory(const MemoryAddress&, const std::vector<std::uint8_t>&, std::vector<std::uint8_t>*, MemoryAccessError*, std::string* error) const)
    AGENT_RUNTIME_UNAVAILABLE(CreateBreakpoint, bool CreateBreakpoint(BreakpointKind, const MemoryAddress&, bool, NativeBreakpoint*, MemoryAccessError*, std::string* error) const)
    AGENT_RUNTIME_UNAVAILABLE(DeleteBreakpoint, bool DeleteBreakpoint(const NativeBreakpoint&, std::string* error) const)
    std::uintptr_t ConsumeLastBreakpointHandle() const override { return 0; }
    AGENT_RUNTIME_UNAVAILABLE(ExecuteDiagnosticCommand, bool ExecuteDiagnosticCommand(const std::string&, std::string*, std::string* error) const)
    AGENT_RUNTIME_UNAVAILABLE(StartTrace, bool StartTrace(const std::string&, std::uint32_t, std::string* error) const)
    AGENT_RUNTIME_UNAVAILABLE(ReadTrace, bool ReadTrace(std::vector<TraceSample>*, bool*, std::string* error) const)
    AGENT_RUNTIME_UNAVAILABLE(StopTrace, bool StopTrace(std::size_t*, std::string* error) const)
#undef AGENT_RUNTIME_UNAVAILABLE

private:
    static void SetUnavailable(std::string* error)
    {
        if (error != NULL)
            *error = "Debugger adapter is not connected in the fake runtime";
    }

    std::uint64_t Launch(const std::uint32_t delay_ms, Command command)
    {
        if (!command)
            return 0;
        const std::uint64_t sequence = next_sequence.fetch_add(1);
        std::thread([delay_ms, sequence, command]() {
            if (delay_ms != 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            command(sequence);
        }).detach();
        return sequence;
    }

    std::atomic<std::uint64_t> next_sequence{1};
    std::unique_ptr<IoBackend> io = AGENT_CreateFakeIoBackend();
};

class RequestLease {
public:
    explicit RequestLease(const std::shared_ptr<AgentServer::Impl>& state) : impl(state)
    {
        std::lock_guard<std::mutex> lock(impl->mutex);
        if (impl->started && !impl->stopping) {
            ++impl->active_requests;
            active = true;
        }
    }

    ~RequestLease()
    {
        if (!active)
            return;
        std::lock_guard<std::mutex> lock(impl->mutex);
        --impl->active_requests;
        if (impl->active_requests == 0)
            impl->lifecycle_changed.notify_all();
    }

    bool IsActive() const { return active; }

private:
    std::shared_ptr<AgentServer::Impl> impl;
    bool active = false;
};

class EmulationLease {
public:
    EmulationLease(const std::shared_ptr<AgentServer::Impl>& state,
                   const std::uint64_t generation) : impl(state), generation(generation)
    {
        std::lock_guard<std::mutex> lock(impl->mutex);
        if (impl->started && !impl->stopping && impl->lifecycle_generation.load() == generation) {
            ++impl->active_emulation_callbacks;
            active = true;
        }
    }

    ~EmulationLease()
    {
        if (!active)
            return;
        std::lock_guard<std::mutex> lock(impl->mutex);
        --impl->active_emulation_callbacks;
        if (impl->active_emulation_callbacks == 0)
            impl->lifecycle_changed.notify_all();
    }

    bool IsActive() const { return active; }

private:
    std::shared_ptr<AgentServer::Impl> impl;
    std::uint64_t generation = 0;
    bool active = false;
};

static std::uint64_t SubmitEmulationCommandWithState(const std::shared_ptr<AgentServer::Impl>& impl,
                                                      const std::shared_ptr<AgentRuntime>& runtime,
                                                      const std::uint64_t generation,
                                                      EmulationThreadQueue::Command command)
{
    return runtime->Submit([impl, runtime, generation, command](const std::uint64_t sequence) {
        EmulationLease lease(impl, generation);
        if (!lease.IsActive())
            return;
        command(sequence);
    });
}

static std::uint64_t SubmitEmulationCommandLocked(const std::shared_ptr<AgentServer::Impl>& impl,
                                                   EmulationThreadQueue::Command command)
{
    if (!impl->started || impl->stopping || !impl->runtime)
        return 0;
    return SubmitEmulationCommandWithState(impl, impl->runtime,
                                            impl->lifecycle_generation.load(),
                                            std::move(command));
}

static std::uint64_t SubmitEmulationCommand(const std::shared_ptr<AgentServer::Impl>& impl,
                                            EmulationThreadQueue::Command command)
{
    std::lock_guard<std::mutex> lock(impl->mutex);
    return SubmitEmulationCommandLocked(impl, std::move(command));
}

static std::uint64_t SubmitEmulationCommandAfter(const std::shared_ptr<AgentServer::Impl>& impl,
                                                 const std::uint32_t delay_ms,
                                                 EmulationThreadQueue::Command command)
{
    std::shared_ptr<AgentRuntime> runtime;
    std::uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lock(impl->mutex);
        if (!impl->started || impl->stopping || !impl->runtime)
            return 0;
        runtime = impl->runtime;
        generation = impl->lifecycle_generation.load();
    }
    return runtime->SubmitAfter(delay_ms, [impl, runtime, generation, command](const std::uint64_t sequence) {
        EmulationLease lease(impl, generation);
        if (!lease.IsActive())
            return;
        command(sequence);
    });
}

static const char* StateName(const AgentServer::Impl::SessionState state)
{
    switch (state) {
    case AgentServer::Impl::SessionState::Starting: return "starting";
    case AgentServer::Impl::SessionState::Stopped: return "stopped";
    case AgentServer::Impl::SessionState::Running: return "running";
    case AgentServer::Impl::SessionState::Exited: return "exited";
    case AgentServer::Impl::SessionState::Failed: return "failed";
    }
    return "failed";
}

static JsonValue SessionResult(const AgentServer::Impl::Session& session)
{
    JsonValue result = Object();
    Add(&result, "session_id", String(session.id));
    Add(&result, "state_revision", Number(session.state_revision));
    return result;
}

static void AppendOutput(AgentServer::Impl::Session* session,
                         const std::string& source,
                         const std::string& message)
{
    if (message.empty())
        return;
    AgentServer::Impl::OutputRecord record;
    record.sequence = session->next_output_sequence++;
    record.timestamp = TimestampMilliseconds();
    record.level = "info";
    record.source = source;
    record.message = message;
    session->output.push_back(record);
    while (session->output.size() > kOutputRingCapacity)
        session->output.pop_front();
}

static bool ReadOutput(const AgentServer::Impl::Session& session,
                       const bool has_cursor,
                       const std::uint64_t cursor,
                       const std::size_t limit,
                       std::vector<AgentServer::Impl::OutputRecord>* records,
                       bool* cursor_expired,
                       bool* has_next_cursor,
                       std::uint64_t* next_cursor)
{
    records->clear();
    *cursor_expired = false;
    *has_next_cursor = false;
    *next_cursor = 0;
    if (session.output.empty()) {
        if (has_cursor && cursor != 0) {
            *cursor_expired = true;
            return false;
        }
        return true;
    }

    const std::uint64_t first_sequence = session.output.front().sequence;
    const std::uint64_t last_sequence = session.output.back().sequence;
    if (has_cursor && (cursor > last_sequence ||
                       (cursor != (std::numeric_limits<std::uint64_t>::max)() && cursor + 1 < first_sequence))) {
        *cursor_expired = true;
        return false;
    }
    const std::uint64_t first_requested = has_cursor ? cursor + 1 : first_sequence;
    for (std::deque<AgentServer::Impl::OutputRecord>::const_iterator it = session.output.begin();
         it != session.output.end() && records->size() < limit; ++it) {
        if (it->sequence >= first_requested)
            records->push_back(*it);
    }
    if (!records->empty() && records->back().sequence < last_sequence) {
        *has_next_cursor = true;
        *next_cursor = records->back().sequence;
    }
    return true;
}

static JsonValue StopReason(const AgentServer::Impl::Session& session)
{
    JsonValue stop = Object();
    Add(&stop, "kind", String(session.last_stop_kind));
    if (!session.last_stop_breakpoint_id.empty())
        Add(&stop, "breakpoint_id", String(session.last_stop_breakpoint_id));
    if (session.has_last_stop_breakpoint_address) {
        Add(&stop, "address", EncodeMemoryAddress(session.last_stop_breakpoint_address));
    } else if (session.last_stop_kind == "startup" || session.last_stop_kind == "step" ||
               session.last_stop_kind == "breakpoint") {
        JsonValue address = Object();
        Add(&address, "space", String("segmented"));
        std::ostringstream segment;
        segment << "0x" << std::uppercase << std::hex << std::setw(4) << std::setfill('0')
                << session.last_stop_segment;
        std::ostringstream offset;
        offset << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0')
               << session.last_stop_instruction_pointer;
        Add(&address, "segment", String(segment.str()));
        Add(&address, "offset", String(offset.str()));
        Add(&stop, "address", address);
    }
    return stop;
}

static std::string Hex32(const std::uint32_t value)
{
    std::ostringstream encoded;
    encoded << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << value;
    return encoded.str();
}

static std::string Hex16(const std::uint16_t value)
{
    std::ostringstream encoded;
    encoded << "0x" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << value;
    return encoded.str();
}

static JsonValue TraceEventResult(const TraceEvent& event, const std::string& detail)
{
    JsonValue result = Object();
    Add(&result, "sequence", Number(event.sequence));
    Add(&result, "address", EncodeMemoryAddress(event.sample.address));
    std::string instruction = event.sample.instruction;
    if (detail == "csip")
        instruction = Hex16(event.sample.address.segment) + ":" + Hex32(event.sample.address.offset);
    else if (detail == "long" && !event.sample.analysis.empty())
        instruction += " ; " + event.sample.analysis;
    Add(&result, "instruction", String(instruction));
    JsonValue changes = Object();
    for (std::vector<TraceRegisterChange>::const_iterator change = event.register_changes.begin();
         change != event.register_changes.end(); ++change) {
        Add(&changes, change->name.c_str(), String(change->value));
    }
    Add(&result, "register_changes", changes);
    return result;
}

static JsonValue RegistersResult(const RegisterSnapshot& registers,
                                 const AgentServer::Impl::Session& session)
{
    JsonValue result = SessionResult(session);
    JsonValue general = Object();
    Add(&general, "eax", String(Hex32(registers.eax)));
    Add(&general, "ebx", String(Hex32(registers.ebx)));
    Add(&general, "ecx", String(Hex32(registers.ecx)));
    Add(&general, "edx", String(Hex32(registers.edx)));
    Add(&general, "esi", String(Hex32(registers.esi)));
    Add(&general, "edi", String(Hex32(registers.edi)));
    Add(&general, "ebp", String(Hex32(registers.ebp)));
    Add(&general, "esp", String(Hex32(registers.esp)));
    Add(&result, "general", general);
    JsonValue segments = Object();
    Add(&segments, "cs", String(Hex16(registers.cs)));
    Add(&segments, "ds", String(Hex16(registers.ds)));
    Add(&segments, "es", String(Hex16(registers.es)));
    Add(&segments, "fs", String(Hex16(registers.fs)));
    Add(&segments, "gs", String(Hex16(registers.gs)));
    Add(&segments, "ss", String(Hex16(registers.ss)));
    Add(&result, "segments", segments);
    Add(&result, "instruction_pointer", String(Hex32(registers.instruction_pointer)));
    Add(&result, "flags", String(Hex32(registers.flags)));
    Add(&result, "cpu_mode", String(registers.cpu_mode));
    return result;
}

static std::string AddressError(const JsonValue& id,
                                const std::string& message,
                                const MemoryAddress& address,
                                const MemoryAccessError& access_error)
{
    JsonValue data = Object();
    Add(&data, "reason", String("ADDRESS_NOT_MAPPED"));
    Add(&data, "space", String(MemorySpaceName(address.space)));
    Add(&data, "address", EncodeMemoryAddress(address));
    Add(&data, "cause", String(access_error.reason.empty() ? "unmapped" : access_error.reason));
    Add(&data, "failing_offset", String(Hex32(access_error.failing_offset)));
    return AGENT_MakeJsonRpcError(id, kErrorAddressNotMapped, message, &data);
}

static std::string SessionError(const JsonValue& id,
                                const int code,
                                const std::string& message,
                                const std::string& reason,
                                const AgentServer::Impl::Session* session)
{
    JsonValue data = Object();
    Add(&data, "reason", String(reason));
    if (session != NULL) {
        Add(&data, "session_id", String(session->id));
        Add(&data, "state", String(StateName(session->state)));
    }
    return AGENT_MakeJsonRpcError(id, code, message, &data);
}

static bool ValidateStartParams(const JsonValue& params,
                                const AgentConfig& config,
                                const std::string& request_path_base,
                                std::string* command,
                                std::vector<std::string>* arguments,
                                std::string* error)
{
    const JsonValue* target = params.Find("target");
    const JsonValue* mounts = params.Find("mounts");
    const JsonValue* break_at = params.Find("break_at");
    if (target == NULL || target->type != JsonType::Object ||
        !GetString(*target, "command", command) || command->empty()) {
        *error = "session.start requires target.command as a non-empty string";
        return false;
    }
    if (break_at == NULL || break_at->type != JsonType::String || break_at->text != "entry") {
        *error = "session.start requires break_at=entry";
        return false;
    }
    if (mounts == NULL || mounts->type != JsonType::Array) {
        *error = "session.start requires mounts as an array";
        return false;
    }
    const JsonValue* json_arguments = target->Find("arguments");
    if (json_arguments != NULL) {
        if (json_arguments->type != JsonType::Array) {
            *error = "target.arguments must be an array";
            return false;
        }
        for (std::size_t index = 0; index < json_arguments->array.size(); ++index) {
            if (json_arguments->array[index].type != JsonType::String) {
                *error = "target.arguments must contain only strings";
                return false;
            }
            arguments->push_back(json_arguments->array[index].text);
        }
    }
    if (mounts->array.size() != 1) {
        *error = "session.start requires exactly one controlled C drive mount";
        return false;
    }

    const JsonValue& mount = mounts->array[0];
    std::string drive;
    std::string host_path;
    if (mount.type != JsonType::Object || !GetString(mount, "drive", &drive) ||
        !GetString(mount, "host_path", &host_path) || drive.size() != 1 || host_path.empty()) {
        *error = "mounts entries require one-letter drive and non-empty host_path";
        return false;
    }
    if (std::toupper(static_cast<unsigned char>(drive[0])) != 'C') {
        *error = "session.start only permits the configured C drive mount";
        return false;
    }

    std::string normalized_requested_path;
    std::string normalized_configured_path;
    if (!NormalizePathForComparison(host_path, request_path_base, &normalized_requested_path) ||
        !NormalizePathForComparison(config.dosbox_workdir, request_path_base, &normalized_configured_path) ||
        normalized_requested_path != normalized_configured_path) {
        *error = "mounts[0].host_path must resolve to the configured dosbox_workdir";
        return false;
    }
    return true;
}

static AgentServer::Impl::Session* FindSession(AgentServer::Impl* impl,
                                                const JsonRpcRequest& request,
                                                std::string* response)
{
    std::string session_id;
    if (!GetString(request.params, "session_id", &session_id)) {
        *response = InvalidParams(request.id, "session_id must be a string");
        return NULL;
    }
    if (!impl->session || impl->session->id != session_id) {
        *response = Error(request.id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
        return NULL;
    }
    return impl->session.get();
}

static bool RebindSessionAfterWait(const std::shared_ptr<AgentServer::Impl>& impl,
                                   const std::string& session_id,
                                   AgentServer::Impl::Session** session,
                                   std::string* response,
                                   const JsonValue& id)
{
    if (!impl->session || impl->session->id != session_id) {
        *session = NULL;
        *response = Error(id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
        return false;
    }
    *session = impl->session.get();
    return true;
}

static const AgentServer::Impl::CachedResponse* FindCachedResponse(const AgentServer::Impl::Session& session,
                                                                    const JsonRpcRequest& request)
{
    if (!request.has_id || request.id.type == JsonType::Null)
        return NULL;
    for (std::deque<AgentServer::Impl::CachedResponse>::const_iterator it = session.completed_requests.begin();
         it != session.completed_requests.end(); ++it) {
        if (it->id_key == request.id_key)
            return &*it;
    }
    return NULL;
}

static void CacheResponse(AgentServer::Impl::Session* session,
                          const JsonRpcRequest& request,
                          const std::string& response)
{
    if (!request.has_id || request.id.type == JsonType::Null)
        return;
    AgentServer::Impl::CachedResponse entry;
    entry.id_key = request.id_key;
    entry.fingerprint = request.fingerprint;
    entry.response = response;
    entry.bytes = entry.id_key.size() + entry.fingerprint.size() + entry.response.size();
    if (entry.bytes > kCompletedResponseCacheByteLimit)
        return;
    session->completed_requests.push_back(entry);
    session->completed_response_bytes += entry.bytes;
    while (session->completed_requests.size() > 1024 ||
           session->completed_response_bytes > kCompletedResponseCacheByteLimit) {
        session->completed_response_bytes -= session->completed_requests.front().bytes;
        session->completed_requests.pop_front();
    }
}

// ---- Guest I/O (session-less) ----

struct IoOperation {
    std::mutex mutex;
    std::condition_variable completed;
    bool done = false;
    bool success = false;
    std::string error;
};

// Runs work on the emulation thread and waits for it. The caller holds impl->mutex
// through `lock`; it is released while waiting so other requests keep flowing.
static bool RunRuntimeCommand(const std::shared_ptr<AgentServer::Impl>& impl,
                              std::unique_lock<std::mutex>& lock,
                              const std::function<bool(AgentRuntime&, std::string*)>& work,
                              std::string* error,
                              bool* timed_out)
{
    *timed_out = false;
    const std::shared_ptr<IoOperation> operation(new IoOperation());
    const std::shared_ptr<AgentRuntime> runtime = impl->runtime;
    if (!runtime || SubmitEmulationCommandLocked(impl, [runtime, operation, work](const std::uint64_t) {
            std::string work_error;
            const bool success = work(*runtime, &work_error);
            {
                std::lock_guard<std::mutex> operation_lock(operation->mutex);
                operation->success = success;
                operation->error = work_error;
                operation->done = true;
            }
            operation->completed.notify_all();
        }) == 0) {
        *error = "Emulation-thread bridge is unavailable";
        return false;
    }
    const std::uint32_t timeout_ms = impl->config.request_timeout_ms;
    lock.unlock();
    bool completed = false;
    {
        std::unique_lock<std::mutex> operation_lock(operation->mutex);
        completed = operation->completed.wait_for(operation_lock, std::chrono::milliseconds(timeout_ms),
                                                  [operation]() { return operation->done; });
    }
    lock.lock();
    if (!completed) {
        *timed_out = true;
        *error = "Timed out waiting for the emulation thread (is DOSBox-X paused in a modal loop?)";
        return false;
    }
    if (!operation->success) {
        *error = operation->error.empty() ? "Guest I/O command failed" : operation->error;
        return false;
    }
    return true;
}

static bool RunIoCommand(const std::shared_ptr<AgentServer::Impl>& impl,
                         std::unique_lock<std::mutex>& lock,
                         const std::function<bool(IoBackend&, std::string*)>& work,
                         std::string* error,
                         bool* timed_out)
{
    return RunRuntimeCommand(impl, lock, [work](AgentRuntime& runtime, std::string* work_error) {
        return work(runtime.Io(), work_error);
    }, error, timed_out);
}

static bool GetNumber(const JsonValue& object, const char* name, double* value)
{
    const JsonValue* field = object.Find(name);
    if (field == NULL || field->type != JsonType::Number)
        return false;
    char* end = NULL;
    *value = std::strtod(field->text.c_str(), &end);
    return end != NULL && *end == '\0';
}

static bool GetOptionalUnsigned(const JsonValue& object, const char* name, std::uint32_t fallback,
                                std::uint32_t* value)
{
    const JsonValue* field = object.Find(name);
    if (field == NULL || field->type == JsonType::Null) {
        *value = fallback;
        return true;
    }
    return GetUnsignedInteger(*field, value);
}

static JsonValue SignedNumber(const std::int64_t value)
{
    return JsonValue::Number(std::to_string(value));
}

static std::string IoError(const JsonValue& id, const bool timed_out, const std::string& message)
{
    return Error(id, timed_out ? kErrorOperationTimeout : kErrorCommandRejected, message,
                 timed_out ? "OPERATION_TIMEOUT" : "COMMAND_REJECTED");
}

static std::string QueueKeyActions(const std::shared_ptr<AgentServer::Impl>& impl,
                                   std::unique_lock<std::mutex>& lock,
                                   const JsonValue& id,
                                   const std::vector<KeyAction>& actions)
{
    std::uint64_t estimated_ms = 0;
    for (std::vector<KeyAction>::const_iterator it = actions.begin(); it != actions.end(); ++it)
        estimated_ms += it->delay_after_ms;
    const std::shared_ptr<std::size_t> pending(new std::size_t(0));
    std::string error;
    bool timed_out = false;
    if (!RunIoCommand(impl, lock, [actions, pending](IoBackend& io, std::string* work_error) {
            return io.QueueKeys(actions, pending.get(), work_error);
        }, &error, &timed_out))
        return IoError(id, timed_out, error);
    JsonValue result = Object();
    Add(&result, "queued_actions", Number(actions.size()));
    Add(&result, "pending_actions", Number(*pending));
    Add(&result, "estimated_emulated_ms", Number(estimated_ms));
    return AGENT_MakeJsonRpcResult(id, result);
}

static std::string SegOff(const std::uint16_t segment, const std::uint32_t offset)
{
    std::ostringstream encoded;
    encoded << std::uppercase << std::hex << std::setfill('0') << std::setw(4) << segment << ":"
            << std::setw(offset > 0xFFFFu ? 8 : 4) << offset;
    return encoded.str();
}

static bool OnEmulationThread(std::string* error)
{
    if (AGENT_EmulationQueue().IsBoundToCurrentThread())
        return true;
    *error = "This operation needs the real emulator (not available in the test runtime)";
    return false;
}

static bool ParseRegisterValue(const JsonValue& value, std::uint32_t* result)
{
    if (value.type == JsonType::Number)
        return GetUnsignedInteger(value, result);
    if (value.type != JsonType::String || value.text.empty())
        return false;
    char* end = NULL;
    const unsigned long long parsed = std::strtoull(value.text.c_str(), &end, 0);
    if (end == NULL || *end != '\0' || parsed > 0xFFFFFFFFull)
        return false;
    *result = static_cast<std::uint32_t>(parsed);
    return true;
}

static JsonValue CallEventJson(const RE_CallEvent& event)
{
    static const char* const kinds[] = { "call", "return", "int", "irq" };
    const char* kind = event.kind == 'C' ? kinds[0] : event.kind == 'R' ? kinds[1] : event.kind == 'I' ? kinds[2] : kinds[3];
    JsonValue item = Object();
    Add(&item, "seq", Number(event.seq));
    Add(&item, "kind", String(kind));
    Add(&item, "far", JsonValue::Bool(event.far_call));
    Add(&item, "depth", Number(event.depth));
    Add(&item, "emulated_ms", JsonValue::Number(std::to_string((long long)event.emulated_ms)));
    Add(&item, "site", String(SegOff(event.site_cs, event.site_ip)));
    if (event.kind == 'I' || event.kind == 'Q')
        Add(&item, "vector", Number(event.target_ip));
    else
        Add(&item, "target", String(SegOff(event.target_cs, event.target_ip)));
    JsonValue registers = Object();
    Add(&registers, "eax", String(Hex32(event.eax)));
    Add(&registers, "ebx", String(Hex32(event.ebx)));
    Add(&registers, "ecx", String(Hex32(event.ecx)));
    Add(&registers, "edx", String(Hex32(event.edx)));
    Add(&registers, "esi", String(Hex32(event.esi)));
    Add(&registers, "edi", String(Hex32(event.edi)));
    Add(&registers, "ebp", String(Hex32(event.ebp)));
    Add(&registers, "esp", String(Hex32(event.esp)));
    Add(&registers, "ds", String(Hex16(event.ds)));
    Add(&registers, "es", String(Hex16(event.es)));
    Add(&item, "registers", registers);
    Add(&item, "text", String(RE_FormatCallEvent(event)));
    return item;
}

static JsonValue CallTraceStatusJson(bool with_functions)
{
    RE_CallTraceStatus status;
    RE_CallTraceGetStatus(&status);
    JsonValue result = Object();
    Add(&result, "state", String(status.armed ? "armed" : status.active ? "recording" : status.finished ? "finished" : "idle"));
    Add(&result, "end_reason", String(status.end_reason));
    Add(&result, "events", Number(status.events));
    Add(&result, "depth", Number(status.depth));
    Add(&result, "function_count", Number(status.functions));
    if (with_functions) {
        std::vector<RE_CallFunction> functions;
        RE_CallTraceFunctions(&functions);
        JsonValue list = JsonValue::Array();
        for (std::size_t index = 0; index < functions.size(); ++index) {
            JsonValue item = Object();
            Add(&item, "address", String(SegOff(functions[index].cs, functions[index].ip)));
            Add(&item, "calls", Number(functions[index].calls));
            Add(&item, "callers", Number(functions[index].callers));
            Add(&item, "min_depth", Number(functions[index].min_depth));
            Add(&item, "first_seq", Number(functions[index].first_seq));
            list.array.push_back(item);
        }
        Add(&result, "functions", list);
    }
    return result;
}

static std::string HandleIoMethod(const std::shared_ptr<AgentServer::Impl>& impl,
                                  const JsonRpcRequest& request,
                                  std::unique_lock<std::mutex>& lock)
{
    const std::string& method = request.method;
    const JsonValue& params = request.params;
    std::string error;
    bool timed_out = false;

    if (method == "input.key") {
        std::string key_name;
        std::string action = "press";
        std::uint32_t hold_ms = 0;
        GetString(params, "action", &action);
        int key = 0;
        if (!GetString(params, "key", &key_name) || !AGENT_LookupKeyName(key_name, &key))
            return InvalidParams(request.id, "input.key requires a known key name (e.g. enter, esc, f1, a, lshift, up)");
        if (!GetOptionalUnsigned(params, "hold_ms", 60, &hold_ms))
            return InvalidParams(request.id, "hold_ms must be a non-negative integer");
        std::vector<KeyAction> actions;
        KeyAction down;
        down.key = key;
        down.pressed = true;
        down.delay_after_ms = hold_ms;
        KeyAction up = down;
        up.pressed = false;
        up.delay_after_ms = 0;
        if (action == "press") {
            actions.push_back(down);
            actions.push_back(up);
        } else if (action == "down") {
            actions.push_back(down);
        } else if (action == "up") {
            actions.push_back(up);
        } else {
            return InvalidParams(request.id, "input.key action must be press, down, or up");
        }
        return QueueKeyActions(impl, lock, request.id, actions);
    }

    if (method == "input.keys") {
        const JsonValue* keys = params.Find("keys");
        std::uint32_t pace_ms = 0;
        std::uint32_t hold_ms = 0;
        if (keys == NULL || keys->type != JsonType::Array || keys->array.empty())
            return InvalidParams(request.id, "input.keys requires keys as a non-empty array of combos like \"ctrl+c\"");
        if (!GetOptionalUnsigned(params, "pace_ms", 40, &pace_ms) ||
            !GetOptionalUnsigned(params, "hold_ms", 60, &hold_ms))
            return InvalidParams(request.id, "pace_ms and hold_ms must be non-negative integers");
        std::vector<KeyAction> actions;
        for (std::size_t index = 0; index < keys->array.size(); ++index) {
            if (keys->array[index].type != JsonType::String)
                return InvalidParams(request.id, "input.keys entries must be strings");
            if (!AGENT_ExpandKeyCombo(keys->array[index].text, hold_ms, pace_ms, &actions, &error))
                return InvalidParams(request.id, error);
        }
        return QueueKeyActions(impl, lock, request.id, actions);
    }

    if (method == "input.type_text") {
        std::string text;
        std::uint32_t pace_ms = 0;
        if (!GetString(params, "text", &text) || text.empty())
            return InvalidParams(request.id, "input.type_text requires a non-empty text string");
        if (!GetOptionalUnsigned(params, "pace_ms", 40, &pace_ms))
            return InvalidParams(request.id, "pace_ms must be a non-negative integer");
        std::vector<KeyAction> actions;
        if (!AGENT_ExpandText(text, pace_ms, &actions, &error))
            return InvalidParams(request.id, error);
        return QueueKeyActions(impl, lock, request.id, actions);
    }

    if (method == "input.clear" || method == "input.status") {
        const bool clear = method == "input.clear";
        const std::shared_ptr<std::size_t> pending(new std::size_t(0));
        if (!RunIoCommand(impl, lock, [clear, pending](IoBackend& io, std::string* work_error) {
                if (clear && !io.ClearKeys(work_error))
                    return false;
                *pending = io.PendingKeys();
                return true;
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "pending_actions", Number(*pending));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "input.mouse") {
        MouseCommand command;
        double x = 0, y = 0, dx = 0, dy = 0, wheel = 0;
        const bool has_x = GetNumber(params, "x", &x);
        const bool has_y = GetNumber(params, "y", &y);
        if (has_x != has_y)
            return InvalidParams(request.id, "input.mouse needs both x and y (0..1 of the screen)");
        command.has_absolute = has_x;
        command.x = static_cast<float>(x);
        command.y = static_cast<float>(y);
        const bool has_dx = GetNumber(params, "dx", &dx);
        const bool has_dy = GetNumber(params, "dy", &dy);
        command.has_relative = has_dx || has_dy;
        command.dx = static_cast<float>(dx);
        command.dy = static_cast<float>(dy);
        std::string button;
        if (GetString(params, "button", &button)) {
            if (button == "left") command.button = 0;
            else if (button == "right") command.button = 1;
            else if (button == "middle") command.button = 2;
            else return InvalidParams(request.id, "button must be left, right, or middle");
            std::string action = "click";
            GetString(params, "action", &action);
            if (action == "click") command.action = MouseButtonAction::Click;
            else if (action == "press") command.action = MouseButtonAction::Press;
            else if (action == "release") command.action = MouseButtonAction::Release;
            else return InvalidParams(request.id, "mouse action must be click, press, or release");
        }
        if (GetNumber(params, "wheel", &wheel))
            command.wheel = static_cast<std::int32_t>(wheel);
        if (!command.has_absolute && !command.has_relative && command.button < 0 && command.wheel == 0)
            return InvalidParams(request.id, "input.mouse needs x/y, dx/dy, button, or wheel");
        if (!RunIoCommand(impl, lock, [command](IoBackend& io, std::string* work_error) {
                return io.Mouse(command, work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "accepted", JsonValue::Bool(true));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "screen.capture") {
        std::string format = "png";
        GetString(params, "format", &format);
        if (format == "raw") {
            const std::shared_ptr<RawFrame> frame(new RawFrame());
            if (!RunIoCommand(impl, lock, [frame](IoBackend& io, std::string* work_error) {
                    return io.CaptureRaw(frame.get(), work_error);
                }, &error, &timed_out))
                return IoError(request.id, timed_out, error);
            JsonValue result = Object();
            Add(&result, "format", String("raw"));
            Add(&result, "width", Number(frame->width));
            Add(&result, "height", Number(frame->height));
            Add(&result, "bpp", Number(frame->bpp));
            Add(&result, "double_width", JsonValue::Bool(frame->double_width));
            Add(&result, "double_height", JsonValue::Bool(frame->double_height));
            Add(&result, "video_mode", String(Hex16(frame->video_mode)));
            Add(&result, "data_base64", String(EncodeBase64(frame->pixels)));
            if (!frame->palette.empty()) {
                JsonValue palette = JsonValue::Array();
                for (std::size_t index = 0; index < frame->palette.size(); ++index) {
                    std::ostringstream color;
                    color << std::uppercase << std::hex << std::setw(6) << std::setfill('0') << frame->palette[index];
                    palette.array.push_back(String(color.str()));
                }
                Add(&result, "palette", palette);
            }
            if (!frame->indices.empty()) {
                Add(&result, "indices_base64", String(EncodeBase64(frame->indices)));
                Add(&result, "indices_source", String("dac_reverse_lookup"));
                Add(&result, "unmatched_pixels", Number(frame->unmatched_pixels));
            }
            return AGENT_MakeJsonRpcResult(request.id, result);
        }
        if (format != "png")
            return InvalidParams(request.id, "screen.capture format must be png or raw");
        const std::shared_ptr<ScreenImage> image(new ScreenImage());
        if (!RunIoCommand(impl, lock, [image](IoBackend& io, std::string* work_error) {
                return io.CaptureScreen(image.get(), work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "format", String("png"));
        Add(&result, "width", Number(image->width));
        Add(&result, "height", Number(image->height));
        Add(&result, "video_mode", String(Hex16(image->video_mode)));
        Add(&result, "data_base64", String(EncodeBase64(image->png)));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "screen.read_text") {
        bool attributes = false;
        bool force = false;
        GetBool(params, "attributes", &attributes);
        GetBool(params, "force", &force);
        const std::shared_ptr<ScreenText> text(new ScreenText());
        if (!RunIoCommand(impl, lock, [attributes, force, text](IoBackend& io, std::string* work_error) {
                return io.ReadScreenText(attributes, force, text.get(), work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "is_text", JsonValue::Bool(text->is_text));
        Add(&result, "video_mode", String(Hex16(text->video_mode)));
        Add(&result, "columns", Number(text->columns));
        Add(&result, "rows", Number(text->rows));
        Add(&result, "page", Number(text->page));
        JsonValue cursor = Object();
        Add(&cursor, "column", Number(text->cursor_column));
        Add(&cursor, "row", Number(text->cursor_row));
        Add(&result, "cursor", cursor);
        JsonValue lines = JsonValue::Array();
        for (std::size_t index = 0; index < text->lines.size(); ++index)
            lines.array.push_back(String(text->lines[index]));
        Add(&result, "lines", lines);
        if (attributes) {
            JsonValue attribute_lines = JsonValue::Array();
            for (std::size_t index = 0; index < text->attributes.size(); ++index)
                attribute_lines.array.push_back(String(text->attributes[index]));
            Add(&result, "attributes", attribute_lines);
        }
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "machine.status") {
        const std::shared_ptr<MachineStatus> status(new MachineStatus());
        if (!RunIoCommand(impl, lock, [status](IoBackend& io, std::string* work_error) {
                return io.GetStatus(status.get(), work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "debugger_active", JsonValue::Bool(status->debugger_active));
        Add(&result, "emulated_ms", Number(status->emulated_ms));
        Add(&result, "cycles", SignedNumber(status->cycles));
        Add(&result, "cycles_auto", JsonValue::Bool(status->cycles_auto));
        Add(&result, "video_mode", String(Hex16(status->video_mode)));
        Add(&result, "is_text", JsonValue::Bool(status->is_text));
        Add(&result, "pending_input_actions", Number(status->pending_input));
        Add(&result, "frame_width", Number(status->frame_width));
        Add(&result, "frame_height", Number(status->frame_height));
        if (impl->session) {
            Add(&result, "session_id", String(impl->session->id));
            Add(&result, "session_state", String(StateName(impl->session->state)));
        }
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "machine.set_speed") {
        std::string cycles;
        GetString(params, "cycles", &cycles);
        int turbo = -1;
        bool turbo_value = false;
        if (GetBool(params, "turbo", &turbo_value))
            turbo = turbo_value ? 1 : 0;
        if (cycles.empty() && turbo < 0)
            return InvalidParams(request.id, "machine.set_speed needs cycles (e.g. \"max\", \"auto\", \"20000\") and/or turbo");
        for (std::string::const_iterator it = cycles.begin(); it != cycles.end(); ++it) {
            if (!std::isalnum(static_cast<unsigned char>(*it)) && *it != ' ' && *it != '%')
                return InvalidParams(request.id, "cycles may only contain letters, digits, spaces and %");
        }
        if (!RunIoCommand(impl, lock, [cycles, turbo](IoBackend& io, std::string* work_error) {
                return io.SetSpeed(cycles, turbo, work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "accepted", JsonValue::Bool(true));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "state.save" || method == "state.load") {
        const JsonValue* slot_value = params.Find("slot");
        std::uint32_t slot = 0;
        std::string path;
        const bool has_path = GetString(params, "path", &path);
        if (has_path) {
            if (!IsAbsolutePath(path))
                return InvalidParams(request.id, method + " path must be an absolute file path");
        } else if (slot_value == NULL || !GetUnsignedInteger(*slot_value, &slot)) {
            return InvalidParams(request.id, method + " requires a non-negative integer slot or an absolute path");
        }
        const bool save = method == "state.save";
        if (!RunIoCommand(impl, lock, [save, slot, path](IoBackend& io, std::string* work_error) {
                return save ? io.SaveStateSlot(slot, path, work_error) : io.LoadStateSlot(slot, path, work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        if (has_path)
            Add(&result, "path", String(path));
        else
            Add(&result, "slot", Number(slot));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "memory.peek" || method == "memory.poke") {
        // Like memory.read/write, but without a session and while the guest keeps running:
        // the access happens between two emulation slices on the emulation thread.
        MemoryAddress address;
        if (!ParseMemoryAddress(params, method.c_str(), &address, &error))
            return InvalidParams(request.id, error);
        const bool peek = method == "memory.peek";
        std::uint32_t length = 0;
        std::vector<std::uint8_t> data;
        if (peek) {
            const JsonValue* length_value = params.Find("length");
            if (length_value == NULL || !GetUnsignedInteger(*length_value, &length) || length == 0 ||
                length > impl->config.max_memory_read_bytes)
                return InvalidParams(request.id, "memory.peek requires 1 <= length <= max_memory_read_bytes");
        } else {
            std::string encoded;
            if (!GetString(params, "data_base64", &encoded) || !DecodeBase64(encoded, &data) || data.empty())
                return InvalidParams(request.id, "memory.poke requires non-empty data_base64");
        }
        const std::shared_ptr<std::vector<std::uint8_t> > bytes(new std::vector<std::uint8_t>(data));
        const std::shared_ptr<MemoryAccessError> access_error(new MemoryAccessError());
        if (!RunRuntimeCommand(impl, lock, [peek, address, length, bytes, access_error](AgentRuntime& runtime, std::string* work_error) {
                if (peek)
                    return runtime.ReadMemory(address, length, bytes.get(), access_error.get(), work_error);
                std::vector<std::uint8_t> after;
                return runtime.WriteMemory(address, *bytes, &after, access_error.get(), work_error);
            }, &error, &timed_out)) {
            if (!access_error->reason.empty())
                return AddressError(request.id, "Guest memory is not accessible at this address", address, *access_error);
            return IoError(request.id, timed_out, error);
        }
        JsonValue result = Object();
        Add(&result, "address", EncodeMemoryAddress(address));
        Add(&result, "byte_count", Number(bytes->size()));
        if (peek)
            Add(&result, "data_base64", String(EncodeBase64(*bytes)));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "mapper.trigger") {
        std::string event;
        if (!GetString(params, "event", &event) || event.empty())
            return InvalidParams(request.id, "mapper.trigger requires an event name such as hand_capture");
        if (!RunIoCommand(impl, lock, [event](IoBackend& io, std::string* work_error) {
                return io.TriggerMapperEvent(event, work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "accepted", JsonValue::Bool(true));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "video.info") {
        const std::shared_ptr<VideoInspectInfo> info(new VideoInspectInfo());
        if (!RunRuntimeCommand(impl, lock, [info](AgentRuntime&, std::string* work_error) {
                if (!OnEmulationThread(work_error))
                    return false;
                VIDEO_GetInspectInfo(info.get());
                return true;
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "machine", String(info->machine));
        Add(&result, "bios_mode", String(Hex16(info->bios_mode)));
        Add(&result, "vga_mode", String(info->vga_mode));
        Add(&result, "is_text", JsonValue::Bool(info->is_text));
        Add(&result, "width", Number(info->width));
        Add(&result, "height", Number(info->height));
        Add(&result, "text_columns", Number(info->text_columns));
        Add(&result, "text_rows", Number(info->text_rows));
        Add(&result, "char_height", Number(info->char_height));
        JsonValue frame = Object();
        Add(&frame, "width", Number(info->render_width));
        Add(&frame, "height", Number(info->render_height));
        Add(&frame, "bpp", Number(info->render_bpp));
        Add(&frame, "double_width", JsonValue::Bool(info->double_width));
        Add(&frame, "double_height", JsonValue::Bool(info->double_height));
        Add(&frame, "fps", JsonValue::Number(std::to_string(info->fps)));
        Add(&result, "frame", frame);
        Add(&result, "dac_bits", Number(info->dac_bits));
        Add(&result, "pel_mask", String(Hex16(info->pel_mask)));
        JsonValue palette = JsonValue::Array();
        JsonValue dac = JsonValue::Array();
        for (int index = 0; index < 256; ++index) {
            std::ostringstream color;
            color << std::uppercase << std::hex << std::setw(6) << std::setfill('0') << info->palette[index];
            palette.array.push_back(String(color.str()));
            std::ostringstream raw;
            raw << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << (unsigned)info->dac_raw[index][0]
                << std::setw(2) << (unsigned)info->dac_raw[index][1] << std::setw(2) << (unsigned)info->dac_raw[index][2];
            dac.array.push_back(String(raw.str()));
        }
        Add(&result, "palette", palette);
        Add(&result, "dac_raw", dac);
        JsonValue attr = JsonValue::Array();
        JsonValue attr_dac = JsonValue::Array();
        for (int index = 0; index < 16; ++index) {
            attr.array.push_back(Number(info->attr_palette[index]));
            attr_dac.array.push_back(Number(info->attr_to_dac[index]));
        }
        Add(&result, "attribute_palette", attr);
        Add(&result, "attribute_to_dac", attr_dac);
        Add(&result, "overscan", Number(info->overscan));
        Add(&result, "color_select", Number(info->color_select));
        Add(&result, "mode_control", Number(info->mode_control));
        Add(&result, "display_start", String(Hex32(info->display_start)));
        Add(&result, "scan_len", Number(info->scan_len));
        Add(&result, "line_compare", Number(info->line_compare));
        Add(&result, "pel_panning", Number(info->pel_panning));
        Add(&result, "chained", JsonValue::Bool(info->chained));
        Add(&result, "cs_ip", String(SegOff(info->cs, info->ip)));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "debug.disassemble") {
        MemoryAddress address;
        if (!ParseMemoryAddress(params, method.c_str(), &address, &error))
            return InvalidParams(request.id, error);
        if (address.space != MemorySpace::Segmented)
            return InvalidParams(request.id, "debug.disassemble needs a segmented address");
        std::uint32_t count = 0;
        if (!GetOptionalUnsigned(params, "count", 16, &count) || count == 0 || count > 500)
            return InvalidParams(request.id, "count must be 1..500");
        const std::shared_ptr<std::vector<RE_DisasmLine> > lines(new std::vector<RE_DisasmLine>());
        if (!RunRuntimeCommand(impl, lock, [address, count, lines](AgentRuntime&, std::string* work_error) {
                return OnEmulationThread(work_error) &&
                       RE_Disassemble(address.segment, address.offset, count, lines.get(), work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        JsonValue list = JsonValue::Array();
        for (std::size_t index = 0; index < lines->size(); ++index) {
            JsonValue item = Object();
            Add(&item, "address", String(SegOff((*lines)[index].seg, (*lines)[index].off)));
            Add(&item, "linear", String(Hex32((*lines)[index].linear)));
            Add(&item, "bytes", String((*lines)[index].bytes));
            Add(&item, "text", String((*lines)[index].text));
            list.array.push_back(item);
        }
        Add(&result, "lines", list);
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "debug.stack") {
        std::uint32_t count = 0;
        if (!GetOptionalUnsigned(params, "count", 32, &count) || count == 0 || count > 1024)
            return InvalidParams(request.id, "count must be 1..1024");
        const std::shared_ptr<RE_StackInfo> info(new RE_StackInfo());
        if (!RunRuntimeCommand(impl, lock, [count, info](AgentRuntime&, std::string* work_error) {
                return OnEmulationThread(work_error) && RE_GetStack(count, info.get(), work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "ss_sp", String(SegOff(info->ss, info->sp)));
        Add(&result, "bp", String(Hex32(info->bp)));
        Add(&result, "cs_ip", String(SegOff(info->cs, info->ip)));
        Add(&result, "big", JsonValue::Bool(info->big));
        JsonValue words = JsonValue::Array();
        for (std::size_t index = 0; index < info->words.size(); ++index)
            words.array.push_back(String(info->big ? Hex32(info->words[index].value) : Hex16((std::uint16_t)info->words[index].value)));
        Add(&result, "words", words);
        JsonValue frames = JsonValue::Array();
        for (std::size_t index = 0; index < info->frames.size(); ++index) {
            const RE_StackFrame& frame = info->frames[index];
            JsonValue item = Object();
            Add(&item, "source", String(frame.source));
            Add(&item, "far", JsonValue::Bool(frame.far_return));
            Add(&item, "stack_offset", String(Hex32(frame.stack_offset)));
            Add(&item, "return", String(SegOff(frame.return_cs, frame.return_ip)));
            Add(&item, "call_site", String(SegOff(frame.call_cs, frame.call_ip)));
            Add(&item, "call_text", String(frame.call_text));
            if (frame.has_target)
                Add(&item, "target", String(SegOff(frame.target_cs, frame.target_ip)));
            frames.array.push_back(item);
        }
        Add(&result, "frames", frames);
        Add(&result, "text", String(RE_FormatStack(*info)));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "state.set_registers") {
        const JsonValue* registers = params.Find("registers");
        if (registers == NULL || registers->type != JsonType::Object || registers->object.empty())
            return InvalidParams(request.id, "state.set_registers requires a registers object, e.g. {\"eax\":\"0x1234\"}");
        std::vector<std::pair<std::string, std::uint32_t> > values;
        for (std::map<std::string, JsonValue>::const_iterator item = registers->object.begin(); item != registers->object.end(); ++item) {
            std::uint32_t value = 0;
            if (!ParseRegisterValue(item->second, &value))
                return InvalidParams(request.id, "register " + item->first + " needs a number or \"0x...\" string");
            values.push_back(std::make_pair(item->first, value));
        }
        if (!RunRuntimeCommand(impl, lock, [values](AgentRuntime&, std::string* work_error) {
                return OnEmulationThread(work_error) && RE_SetRegisters(values, work_error);
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "accepted", JsonValue::Bool(true));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "memory.scratch") {
        const std::shared_ptr<std::uint32_t> scratch(new std::uint32_t[3](), std::default_delete<std::uint32_t[]>());
        if (!RunRuntimeCommand(impl, lock, [scratch](AgentRuntime&, std::string* work_error) {
                std::uint16_t segment = 0, offset = 0;
                std::uint32_t size = 0;
                if (!OnEmulationThread(work_error) || !RE_GetScratch(&segment, &offset, &size, work_error))
                    return false;
                scratch.get()[0] = segment;
                scratch.get()[1] = offset;
                scratch.get()[2] = size;
                return true;
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        JsonValue result = Object();
        Add(&result, "address", String(SegOff((std::uint16_t)scratch.get()[0], scratch.get()[1])));
        Add(&result, "physical", String(Hex32((scratch.get()[0] << 4) + scratch.get()[1])));
        Add(&result, "size", Number(scratch.get()[2]));
        return AGENT_MakeJsonRpcResult(request.id, result);
    }

    if (method == "calltrace.start") {
        RE_CallTraceOptions options;
        const JsonValue* trigger = params.Find("trigger");
        if (trigger != NULL && trigger->type != JsonType::Null) {
            JsonValue wrapper = Object();
            Add(&wrapper, "address", *trigger);
            MemoryAddress address;
            if (!ParseMemoryAddress(wrapper, "calltrace.start trigger", &address, &error) ||
                address.space != MemorySpace::Segmented)
                return InvalidParams(request.id, error.empty() ? "trigger must be a segmented address" : error);
            options.has_trigger = true;
            options.trigger_seg = address.segment;
            options.trigger_off = address.offset;
        }
        std::uint32_t max_events = 0;
        if (!GetOptionalUnsigned(params, "max_events", 100000, &max_events) || max_events == 0 || max_events > 5000000)
            return InvalidParams(request.id, "max_events must be 1..5000000");
        options.max_events = max_events;
        GetBool(params, "include_interrupts", &options.include_interrupts);
        GetBool(params, "include_irq", &options.include_irq);
        options.stop_on_return = options.has_trigger;
        GetBool(params, "stop_on_return", &options.stop_on_return);
        GetBool(params, "break_on_end", &options.break_on_end);
        const std::shared_ptr<JsonValue> status(new JsonValue());
        if (!RunRuntimeCommand(impl, lock, [options, status](AgentRuntime&, std::string* work_error) {
                if (!OnEmulationThread(work_error) || !RE_CallTraceStart(options, work_error))
                    return false;
                *status = CallTraceStatusJson(false);
                return true;
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        return AGENT_MakeJsonRpcResult(request.id, *status);
    }

    if (method == "calltrace.read" || method == "calltrace.stop") {
        const bool stop = method == "calltrace.stop";
        std::uint32_t cursor = 0, limit = 0;
        if (!GetOptionalUnsigned(params, "cursor", 0, &cursor) || !GetOptionalUnsigned(params, "limit", 1000, &limit) ||
            limit == 0 || limit > 20000)
            return InvalidParams(request.id, "cursor must be >= 0 and limit 1..20000");
        bool functions = stop;
        GetBool(params, "functions", &functions);
        const std::shared_ptr<JsonValue> result(new JsonValue());
        if (!RunRuntimeCommand(impl, lock, [stop, cursor, limit, functions, result](AgentRuntime&, std::string* work_error) {
                if (!OnEmulationThread(work_error))
                    return false;
                if (stop)
                    RE_CallTraceStop("stopped by the agent");
                *result = CallTraceStatusJson(functions);
                std::vector<RE_CallEvent> events;
                RE_CallTraceRead(cursor, limit, &events);
                JsonValue list = JsonValue::Array();
                for (std::size_t index = 0; index < events.size(); ++index)
                    list.array.push_back(CallEventJson(events[index]));
                Add(result.get(), "event_list", list);
                Add(result.get(), "next_cursor", Number(events.empty() ? cursor : events.back().seq));
                return true;
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        return AGENT_MakeJsonRpcResult(request.id, *result);
    }

    if (method == "doslog.start" || method == "doslog.stop" || method == "doslog.read") {
        const int action = method == "doslog.start" ? 0 : method == "doslog.stop" ? 1 : 2;
        std::uint32_t cursor = 0, limit = 0;
        if (!GetOptionalUnsigned(params, "cursor", 0, &cursor) || !GetOptionalUnsigned(params, "limit", 1000, &limit) ||
            limit == 0 || limit > 20000)
            return InvalidParams(request.id, "cursor must be >= 0 and limit 1..20000");
        const std::shared_ptr<JsonValue> result(new JsonValue(Object()));
        if (!RunRuntimeCommand(impl, lock, [action, cursor, limit, result](AgentRuntime&, std::string* work_error) {
                if (!OnEmulationThread(work_error))
                    return false;
                if (action == 0) RE_DosLogStart();
                if (action == 1) RE_DosLogStop();
                Add(result.get(), "recording", JsonValue::Bool(RE_DosLogActive()));
                if (action == 2) {
                    std::vector<RE_DosEvent> events;
                    RE_DosLogRead(cursor, limit, &events);
                    JsonValue list = JsonValue::Array();
                    for (std::size_t index = 0; index < events.size(); ++index) {
                        const RE_DosEvent& event = events[index];
                        JsonValue item = Object();
                        Add(&item, "seq", Number(event.seq));
                        Add(&item, "emulated_ms", JsonValue::Number(std::to_string((long long)event.emulated_ms)));
                        Add(&item, "caller", String(SegOff(event.caller_cs, event.caller_ip)));
                        Add(&item, "ah", String(Hex16(event.ah)));
                        Add(&item, "al", String(Hex16(event.al)));
                        Add(&item, "function", String(event.function));
                        Add(&item, "detail", String(event.detail));
                        Add(&item, "text", String(RE_FormatDosEvent(event)));
                        list.array.push_back(item);
                    }
                    Add(result.get(), "event_list", list);
                    Add(result.get(), "next_cursor", Number(events.empty() ? cursor : events.back().seq));
                }
                return true;
            }, &error, &timed_out))
            return IoError(request.id, timed_out, error);
        return AGENT_MakeJsonRpcResult(request.id, *result);
    }

    return AGENT_MakeJsonRpcError(request.id, -32601, "Method not found");
}

// session.attach: debug whatever is running now instead of launching a target.
static std::string HandleSessionAttach(const std::shared_ptr<AgentServer::Impl>& impl,
                                       const JsonRpcRequest& request,
                                       std::unique_lock<std::mutex>& lock)
{
    typedef AgentServer::Impl Impl;
    if (impl->session && impl->session->state != Impl::SessionState::Exited &&
        impl->session->state != Impl::SessionState::Failed)
        return SessionError(request.id, kErrorSessionBusy, "Only one session may be active", "SESSION_BUSY",
                            impl->session.get());

    const std::shared_ptr<MachineStatus> status(new MachineStatus());
    std::string error;
    bool timed_out = false;
    if (!RunIoCommand(impl, lock, [status](IoBackend& io, std::string* work_error) {
            return io.GetStatus(status.get(), work_error);
        }, &error, &timed_out))
        return IoError(request.id, timed_out, error);
    if (impl->session && impl->session->state != Impl::SessionState::Exited &&
        impl->session->state != Impl::SessionState::Failed)
        return SessionError(request.id, kErrorSessionBusy, "Only one session may be active", "SESSION_BUSY",
                            impl->session.get());

    impl->session.reset(new Impl::Session());
    Impl::Session& session = *impl->session;
    session.id = "ses-" + std::to_string(impl->next_session++);
    session.target_command = "(attached)";
    session.attached = true;
    session.trace = TraceStore(impl->config.max_trace_events);
    session.state_revision = 1;
    if (status->debugger_active) {
        session.state = Impl::SessionState::Stopped;
        session.last_stop_kind = "pause";
    } else {
        session.state = Impl::SessionState::Running;
    }
    impl->state_changed.notify_all();
    JsonValue result = SessionResult(session);
    Add(&result, "state", String(StateName(session.state)));
    return AGENT_MakeJsonRpcResult(request.id, result);
}

static std::string Capabilities(const AgentConfig& config)
{
    JsonValue result = Object();
    Add(&result, "protocol_version", String("1.0"));
#if C_DEBUG
    Add(&result, "debugger", JsonValue::Bool(true));
#else
    Add(&result, "debugger", JsonValue::Bool(false));
#endif
    JsonValue trace = Object();
#ifdef C_HEAVY_DEBUG
    Add(&trace, "cpu", JsonValue::Bool(true));
#else
    Add(&trace, "cpu", JsonValue::Bool(false));
#endif
    Add(&result, "trace", trace);
    JsonValue breakpoints = Object();
#ifdef C_HEAVY_DEBUG
    Add(&breakpoints, "memory_change", JsonValue::Bool(true));
#else
    Add(&breakpoints, "memory_change", JsonValue::Bool(false));
#endif
    JsonValue memory_change_spaces = JsonValue::Array();
#ifdef C_HEAVY_DEBUG
    memory_change_spaces.array.push_back(String("segmented"));
    memory_change_spaces.array.push_back(String("linear"));
#endif
    Add(&breakpoints, "memory_change_address_spaces", memory_change_spaces);
    Add(&result, "breakpoints", breakpoints);
    JsonValue spaces = JsonValue::Array();
    spaces.array.push_back(String("segmented"));
    spaces.array.push_back(String("linear"));
    spaces.array.push_back(String("physical"));
    Add(&result, "address_spaces", spaces);
    JsonValue limits = Object();
    Add(&limits, "max_message_bytes", Number(config.max_message_bytes));
    Add(&limits, "max_memory_read_bytes", Number(config.max_memory_read_bytes));
    Add(&limits, "max_trace_events", Number(config.max_trace_events));
    Add(&result, "limits", limits);
    JsonValue io = Object();
    Add(&io, "keyboard", JsonValue::Bool(true));
    Add(&io, "mouse", JsonValue::Bool(true));
#if C_LIBPNG
    Add(&io, "screenshot", JsonValue::Bool(true));
#else
    Add(&io, "screenshot", JsonValue::Bool(false));
#endif
    Add(&io, "screen_text", JsonValue::Bool(true));
    Add(&io, "save_states", JsonValue::Bool(true));
    Add(&io, "session_attach", JsonValue::Bool(true));
    Add(&result, "io", io);
    Add(&result, "raw_debugger_commands", String(config.allow_all_debugger_commands ? "all" : "allowlist"));
    return AGENT_SerializeJson(result);
}

AgentServer::AgentServer() : impl(std::shared_ptr<Impl>(new Impl()))
{}

AgentServer::~AgentServer()
{
    Stop();
}

bool AgentServer::StartFromConfigFile(const std::string& path, std::string* error)
{
    AgentConfig config;
    if (!AGENT_LoadConfigFile(path, &config, error))
        return false;
    return Start(config, error);
}

bool AgentServer::Start(const AgentConfig& config, std::string* error)
{
    const std::shared_ptr<AgentRuntime> runtime(new ProductionAgentRuntime());
    if (!runtime->RequireAvailable(error))
        return false;

    std::unique_ptr<IRpcTransport> transport = AGENT_CreateLocalTransport(config.transport);
    if (!transport) {
        if (error != NULL)
            *error = "No local RPC transport is available";
        return false;
    }
    if (!transport->ValidateConfiguration(config, error))
        return false;

    std::string request_path_base;
    if (!NormalizePathForComparison(".", std::string(), &request_path_base)) {
        if (error != NULL)
            *error = "Unable to resolve the agent startup working directory";
        return false;
    }

    const std::shared_ptr<Impl> state = impl;
    std::unique_lock<std::mutex> lock(impl->mutex);
    if (impl->started || impl->stopping) {
        if (error != NULL)
            *error = impl->stopping ? "Agent server is stopping" : "Agent server is already configured";
        return false;
    }
    impl->config = config;
    impl->transport = std::move(transport);
    impl->runtime = runtime;
    AGENT_SetAllowAllDebuggerCommands(config.allow_all_debugger_commands);
    impl->started = true;
    impl->stopping = false;
    const std::uint64_t generation = ++impl->lifecycle_generation;
    impl->request_path_base = request_path_base;
    AGENT_SetDebuggerStopListener([state, generation](const std::uint16_t segment, const std::uint32_t instruction_pointer) {
        OnDebuggerStopped(state, generation, segment, instruction_pointer);
    });

    if (!impl->transport->Start(config, [state](const std::string& request) {
            return HandleJsonRpcImpl(state, request);
        }, error)) {
        impl->transport.reset();
        impl->runtime.reset();
        impl->started = false;
        impl->stopping = false;
        AGENT_SetDebuggerStopListener(DebuggerStopListener());
        return false;
    }
    return true;
}

bool AgentServer::StartForTest(const AgentConfig& config, std::string* error)
{
    const std::shared_ptr<AgentRuntime> runtime(new FakeAgentRuntime());
    if (!runtime->RequireAvailable(error))
        return false;
    if (config.max_message_bytes == 0 || config.max_memory_read_bytes == 0 || config.max_trace_events == 0) {
        if (error != NULL)
            *error = "Test agent configuration requires non-zero limits";
        return false;
    }

    std::string request_path_base;
    if (!NormalizePathForComparison(".", std::string(), &request_path_base)) {
        if (error != NULL)
            *error = "Unable to resolve the test startup working directory";
        return false;
    }

    std::lock_guard<std::mutex> lock(impl->mutex);
    if (impl->started || impl->stopping) {
        if (error != NULL)
            *error = impl->stopping ? "Agent server is stopping" : "Agent server is already configured";
        return false;
    }
    impl->config = config;
    impl->runtime = runtime;
    impl->started = true;
    impl->stopping = false;
    const std::uint64_t generation = ++impl->lifecycle_generation;
    impl->request_path_base = request_path_base;
    const std::shared_ptr<Impl> state = impl;
    AGENT_SetDebuggerStopListener([state, generation](const std::uint16_t segment, const std::uint32_t instruction_pointer) {
        OnDebuggerStopped(state, generation, segment, instruction_pointer);
    });
    return true;
}

void AgentServer::Stop()
{
    const std::shared_ptr<Impl> state = impl;
    std::unique_ptr<IRpcTransport> transport;
    {
        std::unique_lock<std::mutex> lock(state->mutex);
        if (!state->started) {
            if (!state->stopping)
                return;
            state->lifecycle_changed.wait(lock, [state]() { return !state->stopping; });
            return;
        }
        ++state->lifecycle_generation;
        state->stopping = true;
        state->started = false;
        transport = std::move(state->transport);
        state->state_changed.notify_all();
    }

    // The callback may already have been copied by the emulation thread. It
    // holds shared state and observes stopping, rather than touching this.
    AGENT_SetDebuggerStopListener(DebuggerStopListener());
    if (transport)
        transport->Stop();

    std::unique_lock<std::mutex> lock(state->mutex);
    state->lifecycle_changed.wait(lock, [state]() {
        return state->active_requests == 0 && state->active_emulation_callbacks == 0;
    });
    state->session.reset();
    state->runtime.reset();
    state->stopping = false;
    state->lifecycle_changed.notify_all();
}

bool AgentServer::IsStarted() const
{
    std::unique_lock<std::mutex> lock(impl->mutex);
    return impl->started;
}

const AgentConfig* AgentServer::GetConfig() const
{
    std::lock_guard<std::mutex> lock(impl->mutex);
    return impl->started ? &impl->config : NULL;
}

std::string AgentServer::HandleJsonRpc(const std::string& request)
{
    return HandleJsonRpcImpl(impl, request);
}

std::string AgentServer::HandleJsonRpcImpl(const std::shared_ptr<Impl>& impl, const std::string& request)
{
    RequestLease request_lease(impl);
    if (!request_lease.IsActive())
        return AGENT_MakeJsonRpcError(JsonValue::Null(), -32603, "Agent server is not started");

    AgentConfig config;
    {
        std::lock_guard<std::mutex> lock(impl->mutex);
        if (!impl->started || impl->stopping)
            return AGENT_MakeJsonRpcError(JsonValue::Null(), -32603, "Agent server is not started");
        config = impl->config;
    }
    if (request.size() > config.max_message_bytes) {
        return Error(JsonValue::Null(), kErrorRequestTooLarge,
                     "Request exceeds max_message_bytes", "REQUEST_TOO_LARGE");
    }

    JsonRpcRequest parsed;
    JsonRpcParseError parse_kind = JsonRpcParseError::ParseError;
    std::string parse_error;
    if (!AGENT_ParseJsonRpcRequest(request, &parsed, &parse_kind, &parse_error)) {
        return AGENT_MakeJsonRpcError(JsonValue::Null(),
                                      parse_kind == JsonRpcParseError::ParseError ? -32700 : -32600,
                                      parse_kind == JsonRpcParseError::ParseError ? "Parse error" : "Invalid Request");
    }
    if (!IsKnownMethod(parsed.method))
        return AGENT_MakeJsonRpcError(parsed.id, -32601, "Method not found");

    std::unique_lock<std::mutex> lock(impl->mutex);
    if (parsed.method == "agent.capabilities") {
        if (!parsed.params.object.empty())
            return InvalidParams(parsed.id, "agent.capabilities does not accept params");
        JsonValue result;
        std::string capabilities_error;
        if (!AGENT_ParseJson(Capabilities(impl->config), &result, &capabilities_error))
            return AGENT_MakeJsonRpcError(parsed.id, -32603, "Unable to build capabilities response");
        return AGENT_MakeJsonRpcResult(parsed.id, result);
    }

    if (parsed.method == "trace.start") {
#ifndef C_HEAVY_DEBUG
        return Error(parsed.id, kErrorCapabilityUnavailable,
                     "CPU trace requires a C_HEAVY_DEBUG build", "CAPABILITY_UNAVAILABLE");
#endif
    }

    if (IsIoMethod(parsed.method))
        return HandleIoMethod(impl, parsed, lock);
    if (parsed.method == "session.attach")
        return HandleSessionAttach(impl, parsed, lock);

    if (parsed.method == "session.start") {
        std::string target_command;
        std::vector<std::string> target_arguments;
        std::string validation_error;
        if (impl->session) {
            Impl::Session* existing = impl->session.get();
            if (const Impl::CachedResponse* cached = FindCachedResponse(*existing, parsed)) {
                if (cached->fingerprint != parsed.fingerprint) {
                    return SessionError(parsed.id, kErrorRequestIdConflict,
                                        "request id was already used with a different payload", "REQUEST_ID_CONFLICT",
                                        existing);
                }
                return cached->response;
            }
            if (parsed.has_id && parsed.id.type != JsonType::Null) {
                std::map<std::string, Impl::DeferredRequest>::iterator deferred =
                        existing->deferred_requests.find(parsed.id_key);
                if (deferred != existing->deferred_requests.end()) {
                    if (deferred->second.fingerprint != parsed.fingerprint) {
                        return SessionError(parsed.id, kErrorRequestIdConflict,
                                            "request id was already used with a different payload", "REQUEST_ID_CONFLICT",
                                            existing);
                    }
                    const std::string session_id = existing->id;
                    const Impl::DeferredRequest pending = deferred->second;
                    lock.unlock();
                    const bool completed = pending.wait(impl->config.request_timeout_ms);
                    lock.lock();
                    if (!completed) {
                        return Error(parsed.id, kErrorOperationTimeout,
                                     "The original session.start request is still executing", "OPERATION_TIMEOUT");
                    }
                    if (!impl->session || impl->session->id != session_id)
                        return Error(parsed.id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
                    existing = impl->session.get();
                    deferred = existing->deferred_requests.find(parsed.id_key);
                    if (deferred == existing->deferred_requests.end())
                        return Error(parsed.id, -32603, "Deferred request state was lost", "INTERNAL_ERROR");
                    const std::string completed_response = deferred->second.finish();
                    existing->deferred_requests.erase(deferred);
                    CacheResponse(existing, pending.request, completed_response);
                    return completed_response;
                }
            }
            if (existing->state != Impl::SessionState::Exited && existing->state != Impl::SessionState::Failed)
                return SessionError(parsed.id, kErrorSessionBusy, "Only one session may be active", "SESSION_BUSY", existing);
        }
        if (!ValidateStartParams(parsed.params, impl->config, impl->request_path_base,
                                 &target_command, &target_arguments, &validation_error))
            return InvalidParams(parsed.id, validation_error);

        impl->session.reset(new Impl::Session());
        Impl::Session& session = *impl->session;
        session.id = "ses-" + std::to_string(impl->next_session++);
        session.target_command = target_command;
        session.state = Impl::SessionState::Starting;
        session.trace = TraceStore(impl->config.max_trace_events);
        session.startup_phase = "queued";
        session.startup_deadline = std::chrono::steady_clock::now() +
                std::chrono::milliseconds(impl->config.request_timeout_ms);

        const JsonValue response_id = parsed.id;
        const std::string session_id = session.id;
        Impl::DeferredRequest pending;
        pending.request = parsed;
        pending.fingerprint = parsed.fingerprint;
        pending.wait = [impl, session_id](const std::uint32_t timeout_ms) {
            std::unique_lock<std::mutex> session_lock(impl->mutex);
            return impl->state_changed.wait_for(session_lock, std::chrono::milliseconds(timeout_ms), [impl, &session_id]() {
                return impl->stopping || !impl->session || impl->session->id != session_id ||
                       impl->session->state != Impl::SessionState::Starting;
            });
        };
        pending.finish = [impl, session_id, response_id]() {
            if (!impl->session || impl->session->id != session_id)
                return Error(response_id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
            Impl::Session& active = *impl->session;
            if (active.state == Impl::SessionState::Failed) {
                return SessionError(response_id, kErrorCapabilityUnavailable,
                                    active.failure_message.empty() ? "Unable to launch target" : active.failure_message,
                                    "COMMAND_REJECTED", &active);
            }
            if (active.state != Impl::SessionState::Stopped) {
                return SessionError(response_id, kErrorOperationTimeout,
                                    "Timed out waiting for target entry breakpoint", "OPERATION_TIMEOUT", &active);
            }
            JsonValue result = SessionResult(active);
            Add(&result, "state", String("stopped"));
            Add(&result, "stop_reason", StopReason(active));
            return AGENT_MakeJsonRpcResult(response_id, result);
        };
        if (parsed.has_id && parsed.id.type != JsonType::Null)
            session.deferred_requests[parsed.id_key] = pending;

        const std::string workdir = impl->config.dosbox_workdir;
        if (SubmitEmulationCommandLocked(impl, [impl, session_id, target_command, target_arguments, workdir](const std::uint64_t) {
                StartTargetOnEmulationThread(impl, session_id, target_command, target_arguments, workdir);
            }) == 0) {
            session.state = Impl::SessionState::Failed;
            session.failure_message = "Emulation-thread bridge is unavailable";
        }

        lock.unlock();
        const bool completed = pending.wait(impl->config.request_timeout_ms);
        lock.lock();
        if (!completed) {
            if (impl->session && impl->session->id == session_id &&
                impl->session->state == Impl::SessionState::Starting) {
                impl->session->state = Impl::SessionState::Failed;
                impl->session->failure_message = "Timed out waiting for target entry breakpoint";
                impl->state_changed.notify_all();
            }
            return Error(parsed.id, kErrorOperationTimeout,
                         "Timed out waiting for target entry breakpoint", "OPERATION_TIMEOUT");
        }
        if (!impl->session || impl->session->id != session_id)
            return Error(parsed.id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
        Impl::Session* active = impl->session.get();
        std::string response;
        if (parsed.has_id && parsed.id.type != JsonType::Null) {
            std::map<std::string, Impl::DeferredRequest>::iterator deferred =
                    active->deferred_requests.find(parsed.id_key);
            if (deferred == active->deferred_requests.end())
                return Error(parsed.id, -32603, "Deferred request state was lost", "INTERNAL_ERROR");
            response = deferred->second.finish();
            active->deferred_requests.erase(deferred);
        } else {
            response = pending.finish();
        }
        CacheResponse(active, parsed, response);
        return response;
    }

    std::string response;
    Impl::Session* session = FindSession(impl.get(), parsed, &response);
    if (session == NULL)
        return response;

    if (const Impl::CachedResponse* cached = FindCachedResponse(*session, parsed)) {
        if (cached->fingerprint != parsed.fingerprint) {
            return SessionError(parsed.id, kErrorRequestIdConflict,
                                "request id was already used with a different payload", "REQUEST_ID_CONFLICT", session);
        }
        return cached->response;
    }

    if (!session->deferred_requests.empty() && parsed.method != "session.status" &&
        parsed.method != "execution.wait" && parsed.method != "debug.output.read") {
        std::map<std::string, Impl::DeferredRequest>::iterator deferred = session->deferred_requests.begin();
        const bool retrying_deferred_request = parsed.has_id && parsed.id.type != JsonType::Null &&
                (deferred = session->deferred_requests.find(parsed.id_key)) != session->deferred_requests.end();
        if (retrying_deferred_request && deferred->second.fingerprint != parsed.fingerprint) {
                return SessionError(parsed.id, kErrorRequestIdConflict,
                                    "request id was already used with a different payload", "REQUEST_ID_CONFLICT", session);
        }
        const std::string deferred_session_id = session->id;
        const Impl::DeferredRequest pending = deferred->second;
        lock.unlock();
        const bool completed = pending.wait(impl->config.request_timeout_ms);
        lock.lock();
        if (!completed) {
            return Error(parsed.id, kErrorOperationTimeout,
                         retrying_deferred_request ?
                                 "The original request is still executing on the emulation thread" :
                                 "An earlier request is still executing on the emulation thread",
                         "OPERATION_TIMEOUT");
        }
        if (!impl->session || impl->session->id != deferred_session_id) {
            return Error(parsed.id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
        }
        session = impl->session.get();
        deferred = session->deferred_requests.find(pending.request.id_key);
        if (deferred == session->deferred_requests.end()) {
            return Error(parsed.id, -32603, "Deferred request state was lost", "INTERNAL_ERROR");
        }
        const JsonRpcRequest completed_request = deferred->second.request;
        const std::string completed_response = deferred->second.finish();
        session->deferred_requests.erase(deferred);
        CacheResponse(session, completed_request, completed_response);
        if (retrying_deferred_request)
            return completed_response;
    }

    bool cache_response = true;

    if (parsed.method == "session.status") {
        JsonValue result = SessionResult(*session);
        Add(&result, "state", String(StateName(session->state)));
        JsonValue target = Object();
        Add(&target, "command", String(session->target_command));
        Add(&result, "target", target);
        if (session->state == Impl::SessionState::Starting) {
            JsonValue startup = Object();
            Add(&startup, "phase", String(session->startup_phase));
            Add(&startup, "entry_breakpoint_created", JsonValue::Bool(session->startup_entry_breakpoint_created));
            Add(&result, "startup_diagnostic", startup);
        }
        if (!session->last_stop_kind.empty())
            Add(&result, "last_stop", StopReason(*session));
        response = AGENT_MakeJsonRpcResult(parsed.id, result);
    } else if (parsed.method == "execution.continue") {
        if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target is already running", "TARGET_RUNNING", session);
        } else if (session->state == Impl::SessionState::Exited) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                    "Target has exited", "TARGET_EXITED", session);
        } else if (session->state != Impl::SessionState::Stopped) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                    "Target must be stopped before continuing", "TARGET_NOT_STOPPED", session);
        } else {
            const std::string operation_id = "op-" + std::to_string(session->next_operation++);
            Impl::Operation operation;
            operation.id = operation_id;
            session->operations[operation_id] = operation;
            session->state = Impl::SessionState::Running;
            const std::string session_id = session->id;
            if (SubmitEmulationCommandLocked(impl, [impl, session_id, operation_id](const std::uint64_t) {
                    AgentRuntime& adapter = *impl->runtime;
                    std::string command_error;
                    if (adapter.Continue(&command_error))
                        return;

                    std::lock_guard<std::mutex> command_lock(impl->mutex);
                    if (!impl->session || impl->session->id != session_id ||
                        impl->session->state != Impl::SessionState::Running)
                        return;
                    impl->session->state = Impl::SessionState::Stopped;
                    impl->session->operations.erase(operation_id);
                    impl->session->failure_message = command_error;
                    impl->state_changed.notify_all();
                }) == 0) {
                session->operations.erase(operation_id);
                session->state = Impl::SessionState::Stopped;
                response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                        "Emulation-thread bridge is unavailable", "COMMAND_REJECTED", session);
            } else {
                JsonValue result = SessionResult(*session);
                Add(&result, "operation_id", String(operation_id));
                Add(&result, "state", String("running"));
                response = AGENT_MakeJsonRpcResult(parsed.id, result);
            }
        }
    } else if (parsed.method == "execution.pause") {
        if (session->state != Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                    "Target must be running before it can be paused", "TARGET_NOT_RUNNING", session);
        } else {
            const std::string operation_id = "op-" + std::to_string(session->next_operation++);
            Impl::Operation operation;
            operation.id = operation_id;
            operation.terminal_state = Impl::SessionState::Stopped;
            operation.stop_kind = "pause";
            session->operations[operation_id] = operation;
            session->pending_stop_kind = operation.stop_kind;
            const std::string session_id = session->id;
            if (SubmitEmulationCommandLocked(impl, [impl, session_id, operation_id](const std::uint64_t) {
                        AgentRuntime& adapter = *impl->runtime;
                        std::string command_error;
                        if (adapter.Pause(&command_error))
                            return;

                        std::lock_guard<std::mutex> command_lock(impl->mutex);
                        if (!impl->session || impl->session->id != session_id)
                            return;
                        impl->session->operations.erase(operation_id);
                        impl->session->pending_stop_kind.clear();
                        impl->session->failure_message = command_error;
                        impl->state_changed.notify_all();
                    }) == 0) {
                    session->operations.erase(operation_id);
                    session->pending_stop_kind.clear();
                    response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                            "Emulation-thread bridge is unavailable", "COMMAND_REJECTED", session);
                } else {
                    JsonValue result = SessionResult(*session);
                    Add(&result, "operation_id", String(operation_id));
                    response = AGENT_MakeJsonRpcResult(parsed.id, result);
                }
            }
    } else if (parsed.method == "execution.wait") {
        std::string operation_id;
        const JsonValue* timeout = parsed.params.Find("timeout_ms");
        std::uint32_t timeout_ms = 0;
        if (!GetString(parsed.params, "operation_id", &operation_id) || timeout == NULL ||
            !GetUnsignedInteger(*timeout, &timeout_ms)) {
            response = InvalidParams(parsed.id, "execution.wait requires operation_id and non-negative integer timeout_ms");
        } else {
            std::map<std::string, Impl::Operation>::const_iterator operation = session->operations.find(operation_id);
            if (operation == session->operations.end()) {
                response = InvalidParams(parsed.id, "operation_id is not known for this session");
            } else {
                const std::string session_id = session->id;
                if (!operation->second.complete) {
                    impl->state_changed.wait_for(lock, std::chrono::milliseconds(timeout_ms), [impl, &session_id, &operation_id]() {
                        if (impl->stopping || !impl->session || impl->session->id != session_id)
                            return true;
                        const std::map<std::string, Impl::Operation>::const_iterator pending =
                                impl->session->operations.find(operation_id);
                        return pending == impl->session->operations.end() || pending->second.complete;
                    });
                    if (!impl->session || impl->session->id != session_id) {
                        response = Error(parsed.id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
                    } else {
                        session = impl->session.get();
                        operation = session->operations.find(operation_id);
                    }
                }
                if (!response.empty()) {
                    // The wait invalidated the session; the error response is complete.
                } else if (operation == session->operations.end() || !operation->second.complete) {
                    JsonValue result = SessionResult(*session);
                    Add(&result, "running", JsonValue::Bool(true));
                    response = AGENT_MakeJsonRpcResult(parsed.id, result);
                } else {
                    JsonValue result = SessionResult(*session);
                    Add(&result, "state", String(StateName(operation->second.terminal_state)));
                    Add(&result, "stop_reason", StopReason(*session));
                    response = AGENT_MakeJsonRpcResult(parsed.id, result);
                }
            }
        }
    } else if (parsed.method == "state.get_registers") {
        if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before reading registers", "TARGET_RUNNING", session);
        } else if (session->state == Impl::SessionState::Exited) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable, "Target has exited", "TARGET_EXITED", session);
        } else {
            const std::shared_ptr<Impl::AdapterOperation> operation(new Impl::AdapterOperation());
            const std::string session_id = session->id;
            if (SubmitEmulationCommandLocked(impl, [impl, operation](const std::uint64_t) {
                    AgentRuntime& adapter = *impl->runtime;
                    std::string adapter_error;
                    RegisterSnapshot registers;
                    const bool success = adapter.GetRegisters(&registers, &adapter_error);
                    {
                        std::lock_guard<std::mutex> operation_lock(operation->mutex);
                        operation->success = success;
                        operation->error = adapter_error;
                        operation->registers = registers;
                        operation->done = true;
                    }
                    operation->completed.notify_all();
                }) == 0) {
                response = Error(parsed.id, kErrorCapabilityUnavailable,
                                 "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
            } else {
                std::unique_lock<std::mutex> operation_lock(operation->mutex);
                lock.unlock();
                const bool completed = operation->completed.wait_for(operation_lock,
                        std::chrono::milliseconds(impl->config.request_timeout_ms),
                        [operation]() { return operation->done; });
                lock.lock();
                if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                    return response;
                if (!completed) {
                    response = Error(parsed.id, kErrorOperationTimeout,
                                     "Timed out waiting for state.get_registers on the emulation thread", "OPERATION_TIMEOUT");
                } else if (!operation->success) {
                    response = Error(parsed.id, kErrorCapabilityUnavailable,
                                     operation->error.empty() ? "Unable to capture register state" : operation->error,
                                     "COMMAND_REJECTED");
                } else {
                    response = AGENT_MakeJsonRpcResult(parsed.id, RegistersResult(operation->registers, *session));
                }
            }
        }
    } else if (parsed.method == "memory.read") {
        const JsonValue* length_value = parsed.params.Find("length");
        std::uint32_t length = 0;
        MemoryAddress address;
        std::string validation_error;
        if (!ParseMemoryAddress(parsed.params, "memory.read", &address, &validation_error) ||
            length_value == NULL || !GetUnsignedInteger(*length_value, &length) || length == 0) {
            response = InvalidParams(parsed.id, validation_error.empty() ?
                                     "memory.read requires a positive integer length" : validation_error);
        } else if (length > impl->config.max_memory_read_bytes) {
            response = Error(parsed.id, kErrorRequestTooLarge,
                             "memory.read length exceeds max_memory_read_bytes", "REQUEST_TOO_LARGE");
        } else if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before reading memory", "TARGET_RUNNING", session);
        } else if (session->state == Impl::SessionState::Exited) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable, "Target has exited", "TARGET_EXITED", session);
        } else {
            const std::shared_ptr<Impl::AdapterOperation> operation(new Impl::AdapterOperation());
            const std::string session_id = session->id;
            if (SubmitEmulationCommandLocked(impl, [impl, operation, address, length](const std::uint64_t) {
                    AgentRuntime& adapter = *impl->runtime;
                    std::string adapter_error;
                    std::vector<std::uint8_t> data;
                    MemoryAccessError access_error;
                    const bool success = adapter.ReadMemory(address, length, &data, &access_error, &adapter_error);
                    {
                        std::lock_guard<std::mutex> operation_lock(operation->mutex);
                        operation->success = success;
                        operation->error = adapter_error;
                        operation->access_error = access_error;
                        operation->data.swap(data);
                        operation->done = true;
                    }
                    operation->completed.notify_all();
                }) == 0) {
                response = Error(parsed.id, kErrorCapabilityUnavailable,
                                 "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
            } else {
                std::unique_lock<std::mutex> operation_lock(operation->mutex);
                lock.unlock();
                const bool completed = operation->completed.wait_for(operation_lock,
                        std::chrono::milliseconds(impl->config.request_timeout_ms),
                        [operation]() { return operation->done; });
                lock.lock();
                if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                    return response;
                if (!completed) {
                    response = Error(parsed.id, kErrorOperationTimeout,
                                     "Timed out waiting for memory.read on the emulation thread", "OPERATION_TIMEOUT");
                } else if (!operation->success) {
                    response = AddressError(parsed.id,
                                            operation->error.empty() ? "Unable to access the requested memory range" : operation->error,
                                            address, operation->access_error);
                } else {
                    JsonValue result = SessionResult(*session);
                    Add(&result, "address", EncodeMemoryAddress(address));
                    Add(&result, "byte_count", Number(operation->data.size()));
                    Add(&result, "data_base64", String(EncodeBase64(operation->data)));
                    Add(&result, "sha256", String(Sha256Hex(operation->data)));
                    response = AGENT_MakeJsonRpcResult(parsed.id, result);
                }
            }
        }
    } else if (parsed.method == "session.stop" && session->attached) {
        // Detach: drop this session's breakpoints and let the guest keep running;
        // unlike a launched target, the attached program is never terminated.
        if (session->state != Impl::SessionState::Exited) {
            std::vector<NativeBreakpoint> natives;
            for (std::map<std::string, Impl::Breakpoint>::const_iterator item = session->breakpoints.begin();
                 item != session->breakpoints.end(); ++item)
                natives.push_back(item->second.native);
            const bool resume = session->state == Impl::SessionState::Stopped;
            SubmitEmulationCommandLocked(impl, [impl, natives, resume](const std::uint64_t) {
                AgentRuntime& adapter = *impl->runtime;
                std::string ignored;
                for (std::vector<NativeBreakpoint>::const_iterator native = natives.begin(); native != natives.end(); ++native)
                    adapter.DeleteBreakpoint(*native, &ignored);
                if (resume)
                    adapter.Continue(&ignored);
            });
            session->breakpoints.clear();
            session->trace.Stop();
            session->state = Impl::SessionState::Exited;
            session->last_stop_kind = "detached";
            session->last_stop_breakpoint_id.clear();
            session->has_last_stop_breakpoint_address = false;
            for (std::map<std::string, Impl::Operation>::iterator item = session->operations.begin();
                 item != session->operations.end(); ++item) {
                if (!item->second.complete) {
                    item->second.terminal_state = Impl::SessionState::Exited;
                    item->second.stop_kind = "detached";
                    item->second.complete = true;
                }
            }
            ++session->state_revision;
            impl->state_changed.notify_all();
        }
        JsonValue result = SessionResult(*session);
        Add(&result, "operation_id", String("op-detach-complete"));
        Add(&result, "state", String("exited"));
        response = AGENT_MakeJsonRpcResult(parsed.id, result);
    } else if (parsed.method == "session.stop") {
        if (session->state == Impl::SessionState::Exited) {
            JsonValue result = SessionResult(*session);
            Add(&result, "operation_id", String("op-stop-complete"));
            response = AGENT_MakeJsonRpcResult(parsed.id, result);
        } else if (session->state == Impl::SessionState::Starting ||
                   session->state == Impl::SessionState::Failed) {
            const std::string operation_id = "op-" + std::to_string(session->next_operation++);
            Impl::Operation operation_state;
            operation_state.id = operation_id;
            operation_state.terminal_state = Impl::SessionState::Exited;
            operation_state.stop_kind = "program_exit";
            operation_state.complete = true;
            session->operations[operation_id] = operation_state;
            session->state = Impl::SessionState::Exited;
            session->trace.Stop();
            session->last_stop_kind = "program_exit";
            session->last_stop_breakpoint_id.clear();
            session->has_last_stop_breakpoint_address = false;
            ++session->state_revision;
            impl->state_changed.notify_all();
            JsonValue result = SessionResult(*session);
            Add(&result, "operation_id", String(operation_id));
            response = AGENT_MakeJsonRpcResult(parsed.id, result);
        } else {
            const std::string operation_id = "op-" + std::to_string(session->next_operation++);
            Impl::Operation operation_state;
            operation_state.id = operation_id;
            operation_state.terminal_state = Impl::SessionState::Exited;
            operation_state.stop_kind = "program_exit";
            session->operations[operation_id] = operation_state;
            const std::string session_id = session->id;
            session->termination_deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(impl->config.request_timeout_ms);
            if (SubmitEmulationCommandLocked(impl, [impl, session_id, operation_id](const std::uint64_t) {
                    AgentRuntime& adapter = *impl->runtime;
                    std::string adapter_error;
                    const bool success = adapter.TerminateTarget(&adapter_error);
                    std::lock_guard<std::mutex> command_lock(impl->mutex);
                    if (!impl->session || impl->session->id != session_id)
                        return;
                    Impl::Session& active = *impl->session;
                    std::map<std::string, Impl::Operation>::iterator pending = active.operations.find(operation_id);
                    if (!success || pending == active.operations.end()) {
                        active.failure_message = adapter_error;
                        active.state = Impl::SessionState::Failed;
                        active.last_stop_kind = "fault";
                        if (pending != active.operations.end()) {
                            pending->second.terminal_state = Impl::SessionState::Failed;
                            pending->second.stop_kind = "fault";
                            pending->second.complete = true;
                        }
                        ++active.state_revision;
                        impl->state_changed.notify_all();
                        return;
                    }
                    if (SubmitEmulationCommandLocked(impl, [impl, session_id, operation_id](const std::uint64_t) {
                            CompleteTargetTerminationOnEmulationThread(impl, session_id, operation_id);
                        }) == 0) {
                        active.failure_message = "Emulation-thread bridge is unavailable while completing target termination";
                        active.state = Impl::SessionState::Failed;
                        active.last_stop_kind = "fault";
                        pending->second.terminal_state = Impl::SessionState::Failed;
                        pending->second.stop_kind = "fault";
                        pending->second.complete = true;
                        ++active.state_revision;
                        impl->state_changed.notify_all();
                    }
                }) == 0) {
                session->operations.erase(operation_id);
                response = Error(parsed.id, kErrorCapabilityUnavailable,
                                 "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
            } else {
                JsonValue result = SessionResult(*session);
                Add(&result, "operation_id", String(operation_id));
                response = AGENT_MakeJsonRpcResult(parsed.id, result);
            }
        }
    } else if (parsed.method == "breakpoints.list") {
        if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before listing breakpoints", "TARGET_RUNNING", session);
        } else if (session->state == Impl::SessionState::Exited) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable, "Target has exited", "TARGET_EXITED", session);
        } else {
            JsonValue result = SessionResult(*session);
            JsonValue entries = JsonValue::Array();
            for (std::map<std::string, Impl::Breakpoint>::const_iterator item = session->breakpoints.begin();
                 item != session->breakpoints.end(); ++item) {
                JsonValue entry = Object();
                Add(&entry, "breakpoint_id", String(item->second.id));
                Add(&entry, "kind", String(item->second.native.kind == BreakpointKind::Execution ? "execution" : "memory_change"));
                Add(&entry, "enabled", JsonValue::Bool(item->second.enabled));
                Add(&entry, "once", JsonValue::Bool(item->second.native.once));
                Add(&entry, "address", EncodeMemoryAddress(item->second.native.address));
                entries.array.push_back(entry);
            }
            Add(&result, "breakpoints", entries);
            response = AGENT_MakeJsonRpcResult(parsed.id, result);
        }
    } else if (parsed.method == "breakpoints.create") {
        std::string kind_name;
        std::string validation_error;
        MemoryAddress address;
        bool once = false;
        const JsonValue* once_value = parsed.params.Find("once");
        if (!GetString(parsed.params, "kind", &kind_name) || (kind_name != "execution" && kind_name != "memory_change") ||
            !ParseMemoryAddress(parsed.params, "breakpoints.create", &address, &validation_error) ||
            (once_value != NULL && !GetBool(parsed.params, "once", &once))) {
            response = InvalidParams(parsed.id, validation_error.empty() ?
                                     "breakpoints.create requires kind, address, and optional boolean once" : validation_error);
        } else if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before creating breakpoints", "TARGET_RUNNING", session);
        } else if (session->state != Impl::SessionState::Stopped) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                    "Target must be stopped before creating breakpoints", "TARGET_NOT_STOPPED", session);
        } else {
            const BreakpointKind kind = kind_name == "execution" ? BreakpointKind::Execution : BreakpointKind::MemoryChange;
#ifndef C_HEAVY_DEBUG
            if (kind == BreakpointKind::MemoryChange) {
                response = Error(parsed.id, kErrorCapabilityUnavailable,
                                 "Memory-change breakpoints require C_HEAVY_DEBUG", "CAPABILITY_UNAVAILABLE");
            } else
#endif
            {
                const std::shared_ptr<Impl::AdapterOperation> operation(new Impl::AdapterOperation());
                if (SubmitEmulationCommandLocked(impl, [impl, operation, kind, address, once](const std::uint64_t) {
                        AgentRuntime& adapter = *impl->runtime;
                        std::string adapter_error;
                        MemoryAccessError access_error;
                        NativeBreakpoint breakpoint;
                        const bool success = adapter.CreateBreakpoint(kind, address, once, &breakpoint, &access_error, &adapter_error);
                        {
                            std::lock_guard<std::mutex> operation_lock(operation->mutex);
                            operation->success = success;
                            operation->error = adapter_error;
                            operation->access_error = access_error;
                            operation->breakpoint = breakpoint;
                            operation->done = true;
                        }
                        operation->completed.notify_all();
                }) == 0) {
                    response = Error(parsed.id, kErrorCapabilityUnavailable,
                                     "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
                } else {
                    const JsonValue response_id = parsed.id;
                    const std::string session_id = session->id;
                    Impl::DeferredRequest pending;
                    pending.request = parsed;
                    pending.fingerprint = parsed.fingerprint;
                    pending.wait = [operation](const std::uint32_t timeout_ms) {
                        std::unique_lock<std::mutex> operation_lock(operation->mutex);
                        return operation->completed.wait_for(operation_lock, std::chrono::milliseconds(timeout_ms),
                                                             [operation]() { return operation->done; });
                    };
                    pending.finish = [impl, session_id, response_id, operation, address, kind, kind_name, once]() {
                        if (!operation->success) {
                            if (!operation->access_error.reason.empty())
                                return AddressError(response_id, "Unable to resolve breakpoint address", address, operation->access_error);
                            if (kind == BreakpointKind::MemoryChange)
                                return Error(response_id, kErrorCapabilityUnavailable,
                                             operation->error.empty() ? "Memory-change breakpoint is unavailable" : operation->error,
                                             "CAPABILITY_UNAVAILABLE");
                            return Error(response_id, kErrorCapabilityUnavailable,
                                         operation->error.empty() ? "Debugger rejected breakpoint" : operation->error,
                                         "COMMAND_REJECTED");
                        }
                        if (!impl->session || impl->session->id != session_id)
                            return Error(response_id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
                        Impl::Session& active = *impl->session;
                        Impl::Breakpoint breakpoint;
                        breakpoint.id = "bp-" + std::to_string(active.next_breakpoint++);
                        breakpoint.native = operation->breakpoint;
                        active.breakpoints[breakpoint.id] = breakpoint;
                        ++active.state_revision;
                        JsonValue result = SessionResult(active);
                        Add(&result, "breakpoint_id", String(breakpoint.id));
                        Add(&result, "kind", String(kind_name));
                        Add(&result, "once", JsonValue::Bool(once));
                        Add(&result, "address", EncodeMemoryAddress(breakpoint.native.address));
                        return AGENT_MakeJsonRpcResult(response_id, result);
                    };
                    if (parsed.has_id && parsed.id.type != JsonType::Null)
                        session->deferred_requests[parsed.id_key] = pending;

                    lock.unlock();
                    const bool completed = pending.wait(impl->config.request_timeout_ms);
                    lock.lock();
                    if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                        return response;
                    if (!completed) {
                        if (parsed.has_id && parsed.id.type != JsonType::Null)
                            cache_response = false;
                        response = Error(parsed.id, kErrorOperationTimeout,
                                         "Timed out creating breakpoint on the emulation thread", "OPERATION_TIMEOUT");
                    } else if (parsed.has_id && parsed.id.type != JsonType::Null) {
                        std::map<std::string, Impl::DeferredRequest>::iterator deferred =
                                session->deferred_requests.find(parsed.id_key);
                        response = deferred->second.finish();
                        session->deferred_requests.erase(deferred);
                    } else {
                        response = pending.finish();
                    }
                }
            }
        }
    } else if (parsed.method == "breakpoints.delete") {
        std::string breakpoint_id;
        if (!GetString(parsed.params, "breakpoint_id", &breakpoint_id)) {
            response = InvalidParams(parsed.id, "breakpoints.delete requires breakpoint_id");
        } else if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before deleting breakpoints", "TARGET_RUNNING", session);
        } else if (session->state != Impl::SessionState::Stopped) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                    "Target must be stopped before deleting breakpoints", "TARGET_NOT_STOPPED", session);
        } else {
            std::map<std::string, Impl::Breakpoint>::iterator item = session->breakpoints.find(breakpoint_id);
            if (item == session->breakpoints.end()) {
                response = Error(parsed.id, kErrorBreakpointNotFound, "Breakpoint was not found", "BREAKPOINT_NOT_FOUND");
            } else {
                const NativeBreakpoint native = item->second.native;
                const std::shared_ptr<Impl::AdapterOperation> operation(new Impl::AdapterOperation());
                if (SubmitEmulationCommandLocked(impl, [impl, operation, native](const std::uint64_t) {
                        AgentRuntime& adapter = *impl->runtime;
                        std::string adapter_error;
                        const bool success = adapter.DeleteBreakpoint(native, &adapter_error);
                        {
                            std::lock_guard<std::mutex> operation_lock(operation->mutex);
                            operation->success = success;
                            operation->error = adapter_error;
                            operation->done = true;
                        }
                        operation->completed.notify_all();
                }) == 0) {
                    response = Error(parsed.id, kErrorCapabilityUnavailable,
                                     "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
                } else {
                    const JsonValue response_id = parsed.id;
                    const std::string session_id = session->id;
                    Impl::DeferredRequest pending;
                    pending.request = parsed;
                    pending.fingerprint = parsed.fingerprint;
                    pending.wait = [operation](const std::uint32_t timeout_ms) {
                        std::unique_lock<std::mutex> operation_lock(operation->mutex);
                        return operation->completed.wait_for(operation_lock, std::chrono::milliseconds(timeout_ms),
                                                             [operation]() { return operation->done; });
                    };
                    pending.finish = [impl, session_id, response_id, operation, breakpoint_id]() {
                        if (!operation->success) {
                            return Error(response_id, kErrorBreakpointNotFound,
                                         operation->error.empty() ? "Breakpoint was not found" : operation->error,
                                         "BREAKPOINT_NOT_FOUND");
                        }
                        if (!impl->session || impl->session->id != session_id)
                            return Error(response_id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
                        Impl::Session& active = *impl->session;
                        active.breakpoints.erase(breakpoint_id);
                        ++active.state_revision;
                        JsonValue result = SessionResult(active);
                        Add(&result, "breakpoint_id", String(breakpoint_id));
                        Add(&result, "deleted", JsonValue::Bool(true));
                        return AGENT_MakeJsonRpcResult(response_id, result);
                    };
                    if (parsed.has_id && parsed.id.type != JsonType::Null)
                        session->deferred_requests[parsed.id_key] = pending;

                    lock.unlock();
                    const bool completed = pending.wait(impl->config.request_timeout_ms);
                    lock.lock();
                    if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                        return response;
                    if (!completed) {
                        if (parsed.has_id && parsed.id.type != JsonType::Null)
                            cache_response = false;
                        response = Error(parsed.id, kErrorOperationTimeout,
                                         "Timed out deleting breakpoint on the emulation thread", "OPERATION_TIMEOUT");
                    } else if (parsed.has_id && parsed.id.type != JsonType::Null) {
                        std::map<std::string, Impl::DeferredRequest>::iterator deferred =
                                session->deferred_requests.find(parsed.id_key);
                        response = deferred->second.finish();
                        session->deferred_requests.erase(deferred);
                    } else {
                        response = pending.finish();
                    }
                }
            }
        }
    } else if (parsed.method == "execution.step") {
        std::string mode;
        if (!GetString(parsed.params, "mode", &mode) || (mode != "into" && mode != "over")) {
            response = InvalidParams(parsed.id, "execution.step requires mode=into or mode=over");
        } else if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before single-stepping", "TARGET_RUNNING", session);
        } else if (session->state != Impl::SessionState::Stopped) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                    "Target must be stopped before single-stepping", "TARGET_NOT_STOPPED", session);
        } else {
            const std::shared_ptr<Impl::StepOperation> operation(new Impl::StepOperation());
            operation->dispatch.reset(new Impl::AdapterOperation());
            operation->registers.reset(new Impl::AdapterOperation());
            const StepMode step_mode = mode == "into" ? StepMode::Into : StepMode::Over;
            const std::string session_id = session->id;
            if (SubmitEmulationCommandLocked(impl, [impl, operation, step_mode, session_id](const std::uint64_t) {
                AgentRuntime& adapter = *impl->runtime;
                std::string adapter_error;
                bool continued = false;
                RegisterSnapshot registers;
                bool success = adapter.Step(step_mode, &continued, &adapter_error);
                if (success && !continued)
                    success = adapter.GetRegisters(&registers, &adapter_error);
                {
                    std::lock_guard<std::mutex> operation_lock(operation->dispatch->mutex);
                    operation->dispatch->success = success;
                    operation->dispatch->continued = continued;
                    operation->dispatch->error = adapter_error;
                    operation->dispatch->registers = registers;
                    operation->dispatch->done = true;
                }
                if (success && continued) {
                    std::lock_guard<std::mutex> session_lock(impl->mutex);
                    if (impl->session && impl->session->id == session_id &&
                        impl->session->state == Impl::SessionState::Stopped) {
                        impl->session->state = Impl::SessionState::Running;
                        impl->session->pending_stop_kind = "step";
                        impl->state_changed.notify_all();
                    }
                }
                operation->dispatch->completed.notify_all();
                }) == 0) {
                response = Error(parsed.id, kErrorCapabilityUnavailable,
                                 "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
            } else {
                const JsonValue response_id = parsed.id;
                Impl::DeferredRequest pending;
                pending.request = parsed;
                pending.fingerprint = parsed.fingerprint;
                pending.wait = [impl, session_id, operation](const std::uint32_t timeout_ms) {
                    {
                        std::unique_lock<std::mutex> dispatch_lock(operation->dispatch->mutex);
                        if (!operation->dispatch->completed.wait_for(dispatch_lock, std::chrono::milliseconds(timeout_ms),
                                                                     [operation]() { return operation->dispatch->done; })) {
                            return false;
                        }
                        if (!operation->dispatch->success || !operation->dispatch->continued)
                            return true;
                    }

                    {
                        std::unique_lock<std::mutex> session_lock(impl->mutex);
                        if (!impl->state_changed.wait_for(session_lock, std::chrono::milliseconds(timeout_ms),
                                                          [impl, &session_id]() {
                            return impl->stopping || !impl->session || impl->session->id != session_id ||
                                   impl->session->state != Impl::SessionState::Running;
                        })) {
                            return false;
                        }
                        if (!impl->session || impl->session->id != session_id)
                            return true;
                    }

                    bool submit_registers = false;
                    {
                        std::lock_guard<std::mutex> step_lock(operation->mutex);
                        if (!operation->registers_submitted) {
                            operation->registers_submitted = true;
                            submit_registers = true;
                        }
                    }
                    if (submit_registers && SubmitEmulationCommand(impl, [impl, operation](const std::uint64_t) {
                            AgentRuntime& adapter = *impl->runtime;
                            std::string registers_error;
                            RegisterSnapshot registers;
                            const bool success = adapter.GetRegisters(&registers, &registers_error);
                            {
                                std::lock_guard<std::mutex> registers_lock(operation->registers->mutex);
                                operation->registers->success = success;
                                operation->registers->error = registers_error;
                                operation->registers->registers = registers;
                                operation->registers->done = true;
                            }
                            operation->registers->completed.notify_all();
                        }) == 0) {
                        std::lock_guard<std::mutex> registers_lock(operation->registers->mutex);
                        operation->registers->success = false;
                        operation->registers->error = "Emulation-thread bridge is unavailable";
                        operation->registers->done = true;
                        operation->registers->completed.notify_all();
                    }

                    std::unique_lock<std::mutex> registers_lock(operation->registers->mutex);
                    return operation->registers->completed.wait_for(registers_lock, std::chrono::milliseconds(timeout_ms),
                                                                    [operation]() { return operation->registers->done; });
                };
                pending.finish = [impl, session_id, response_id, operation]() {
                    bool dispatch_success = false;
                    bool continued = false;
                    std::string dispatch_error;
                    RegisterSnapshot dispatch_registers;
                    {
                        std::lock_guard<std::mutex> dispatch_lock(operation->dispatch->mutex);
                        dispatch_success = operation->dispatch->success;
                        continued = operation->dispatch->continued;
                        dispatch_error = operation->dispatch->error;
                        dispatch_registers = operation->dispatch->registers;
                    }
                    if (!dispatch_success) {
                        return Error(response_id, kErrorCapabilityUnavailable,
                                     dispatch_error.empty() ? "Debugger rejected execution.step" : dispatch_error,
                                     "COMMAND_REJECTED");
                    }
                    if (!impl->session || impl->session->id != session_id)
                        return Error(response_id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
                    Impl::Session& active = *impl->session;
                    if (!continued) {
                        active.last_stop_kind = "step";
                        active.last_stop_breakpoint_id.clear();
                        active.has_last_stop_breakpoint_address = false;
                        active.last_stop_segment = dispatch_registers.cs;
                        active.last_stop_instruction_pointer = dispatch_registers.instruction_pointer;
                        ++active.state_revision;
                        JsonValue result = SessionResult(active);
                        Add(&result, "stop_reason", StopReason(active));
                        Add(&result, "registers", RegistersResult(dispatch_registers, active));
                        return AGENT_MakeJsonRpcResult(response_id, result);
                    }
                    if (active.state != Impl::SessionState::Stopped) {
                        return SessionError(response_id, kErrorCapabilityUnavailable,
                                            "Target did not stop after execution.step over", "TARGET_NOT_STOPPED", &active);
                    }
                    bool registers_success = false;
                    std::string registers_error;
                    RegisterSnapshot registers;
                    {
                        std::lock_guard<std::mutex> registers_lock(operation->registers->mutex);
                        registers_success = operation->registers->success;
                        registers_error = operation->registers->error;
                        registers = operation->registers->registers;
                    }
                    if (!registers_success) {
                        return Error(response_id, kErrorCapabilityUnavailable,
                                     registers_error.empty() ?
                                             "Unable to collect registers after execution.step over" : registers_error,
                                     "COMMAND_REJECTED");
                    }
                    JsonValue result = SessionResult(active);
                    Add(&result, "stop_reason", StopReason(active));
                    Add(&result, "registers", RegistersResult(registers, active));
                    return AGENT_MakeJsonRpcResult(response_id, result);
                };
                if (parsed.has_id && parsed.id.type != JsonType::Null)
                    session->deferred_requests[parsed.id_key] = pending;

                lock.unlock();
                const bool completed = pending.wait(impl->config.request_timeout_ms);
                lock.lock();
                if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                    return response;
                if (!completed) {
                    if (parsed.has_id && parsed.id.type != JsonType::Null)
                        cache_response = false;
                    response = Error(parsed.id, kErrorOperationTimeout,
                                     "Timed out waiting for execution.step to complete", "OPERATION_TIMEOUT");
                } else if (parsed.has_id && parsed.id.type != JsonType::Null) {
                    std::map<std::string, Impl::DeferredRequest>::iterator deferred =
                            session->deferred_requests.find(parsed.id_key);
                    response = deferred->second.finish();
                    session->deferred_requests.erase(deferred);
                } else {
                    response = pending.finish();
                }
            }
        }
    } else if (parsed.method == "memory.write") {
        if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before inspecting or modifying state", "TARGET_RUNNING", session);
        } else if (session->state == Impl::SessionState::Exited) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                    "Target has exited", "TARGET_EXITED", session);
        } else {
            MemoryAddress address;
            std::string validation_error;
            std::vector<std::uint8_t> bytes;
            const JsonValue* data_base64 = parsed.params.Find("data_base64");
            const JsonValue* expected_sha256 = parsed.params.Find("expected_sha256");
            bool has_expected_sha256 = false;
            std::string normalized_expected_sha256;
            if (!ParseMemoryAddress(parsed.params, "memory.write", &address, &validation_error)) {
                response = InvalidParams(parsed.id, validation_error);
            } else if (data_base64 == NULL || data_base64->type != JsonType::String ||
                       !DecodeBase64(data_base64->text, &bytes) || bytes.empty() ||
                       bytes.size() > impl->config.max_memory_read_bytes) {
                response = Error(parsed.id, kErrorInvalidBinaryLength,
                                 "data_base64 must decode to between 1 and max_memory_read_bytes bytes",
                                 "INVALID_BINARY_LENGTH");
            } else if (expected_sha256 != NULL &&
                       (expected_sha256->type != JsonType::String ||
                        !NormalizeSha256(expected_sha256->text, &normalized_expected_sha256))) {
                response = InvalidParams(parsed.id, "expected_sha256 must be a 64-character hexadecimal SHA-256 value");
            } else {
                has_expected_sha256 = expected_sha256 != NULL;
                const std::shared_ptr<Impl::MemoryWriteOperation> operation(new Impl::MemoryWriteOperation());
                const std::string session_id = session->id;
                if (SubmitEmulationCommandLocked(impl, [impl, operation, address, bytes, has_expected_sha256,
                                                    normalized_expected_sha256](const std::uint64_t) {
                        AgentRuntime& adapter = *impl->runtime;
                        std::string adapter_error;
                        std::vector<std::uint8_t> before;
                        std::vector<std::uint8_t> after;
                        MemoryAccessError access_error;
                        bool success = adapter.ReadMemory(address, bytes.size(), &before, &access_error, &adapter_error);
                        bool precondition_failed = false;
                        if (success && has_expected_sha256 && Sha256Hex(before) != normalized_expected_sha256) {
                            success = false;
                            precondition_failed = true;
                        }
                        if (success)
                            success = adapter.WriteMemory(address, bytes, &after, &access_error, &adapter_error);

                        {
                            std::lock_guard<std::mutex> operation_lock(operation->mutex);
                            operation->before.swap(before);
                            operation->after.swap(after);
                            operation->precondition_failed = precondition_failed;
                            operation->success = success;
                        operation->error = adapter_error;
                        operation->access_error = access_error;
                            operation->done = true;
                        }
                        operation->completed.notify_all();
                }) == 0) {
                    response = Error(parsed.id, kErrorCapabilityUnavailable,
                                     "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
                } else {
                    const JsonValue response_id = parsed.id;
                    Impl::DeferredRequest pending;
                    pending.request = parsed;
                    pending.fingerprint = parsed.fingerprint;
                    pending.wait = [operation](const std::uint32_t timeout_ms) {
                        std::unique_lock<std::mutex> operation_lock(operation->mutex);
                        return operation->completed.wait_for(operation_lock, std::chrono::milliseconds(timeout_ms),
                                                             [operation]() { return operation->done; });
                    };
                    pending.finish = [impl, session_id, response_id, operation, address]() {
                        if (operation->precondition_failed) {
                            return Error(response_id, kErrorMemoryPreconditionFailed,
                                         "expected_sha256 does not match the current memory contents",
                                         "MEMORY_PRECONDITION_FAILED");
                        }
                        if (!operation->success) {
                            return AddressError(response_id,
                                                operation->error.empty() ? "Unable to access the requested memory range" : operation->error,
                                                address, operation->access_error);
                        }
                        if (!impl->session || impl->session->id != session_id) {
                            return Error(response_id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
                        }
                        Impl::Session& active = *impl->session;
                        ++active.state_revision;
                        JsonValue result = SessionResult(active);
                        Add(&result, "address", EncodeMemoryAddress(address));
                        Add(&result, "before_sha256", String(Sha256Hex(operation->before)));
                        Add(&result, "after_sha256", String(Sha256Hex(operation->after)));
                        Add(&result, "byte_count", Number(operation->after.size()));
                        return AGENT_MakeJsonRpcResult(response_id, result);
                    };

                    if (parsed.has_id && parsed.id.type != JsonType::Null)
                        session->deferred_requests[parsed.id_key] = pending;

                    lock.unlock();
                    const bool completed = pending.wait(impl->config.request_timeout_ms);
                    lock.lock();
                    if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                        return response;
                    if (!completed) {
                        if (parsed.has_id && parsed.id.type != JsonType::Null) {
                            cache_response = false;
                            response = Error(parsed.id, kErrorOperationTimeout,
                                             "Timed out waiting for memory.write on the emulation thread", "OPERATION_TIMEOUT");
                        } else {
                            response = Error(parsed.id, kErrorOperationTimeout,
                                             "Timed out waiting for memory.write on the emulation thread", "OPERATION_TIMEOUT");
                        }
                    } else if (parsed.has_id && parsed.id.type != JsonType::Null) {
                        std::map<std::string, Impl::DeferredRequest>::iterator deferred =
                                session->deferred_requests.find(parsed.id_key);
                        response = deferred->second.finish();
                        session->deferred_requests.erase(deferred);
                    } else {
                        response = pending.finish();
                    }
                }
            }
        }
    } else if (parsed.method == "state.get_registers" || parsed.method == "memory.read" ||
               parsed.method == "breakpoints.create" || parsed.method == "breakpoints.list" || parsed.method == "breakpoints.delete" ||
               parsed.method == "execution.step") {
        if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before inspecting or modifying state", "TARGET_RUNNING", session);
        } else if (session->state == Impl::SessionState::Exited) {
            response = SessionError(parsed.id, kErrorCapabilityUnavailable,
                                    "Target has exited", "TARGET_EXITED", session);
        } else {
            response = Error(parsed.id, kErrorCapabilityUnavailable,
                             "This debugger adapter operation is not available until phase C", "CAPABILITY_UNAVAILABLE");
        }
    } else if (parsed.method == "debug.output.read") {
        const JsonValue* limit_value = parsed.params.Find("limit");
        bool has_cursor = false;
        std::uint64_t cursor = 0;
        std::uint32_t limit = 0;
        if (!ParseCursor(parsed.params.Find("cursor"), "out", &has_cursor, &cursor) ||
            limit_value == NULL || !GetUnsignedInteger(*limit_value, &limit) || limit == 0) {
            response = InvalidParams(parsed.id,
                                     "debug.output.read requires cursor=null|out-N and a positive integer limit");
        } else {
            std::vector<Impl::OutputRecord> records;
            bool cursor_expired = false;
            bool has_next_cursor = false;
            std::uint64_t next_cursor = 0;
            if (!ReadOutput(*session, has_cursor, cursor, limit, &records, &cursor_expired,
                            &has_next_cursor, &next_cursor)) {
                response = Error(parsed.id, kErrorCursorExpired,
                                 "debug.output cursor is no longer available", "CURSOR_EXPIRED");
            } else {
                JsonValue result = SessionResult(*session);
                JsonValue output = JsonValue::Array();
                for (std::vector<Impl::OutputRecord>::const_iterator item = records.begin(); item != records.end(); ++item) {
                    JsonValue record = Object();
                    Add(&record, "sequence", Number(item->sequence));
                    Add(&record, "timestamp", Number(item->timestamp));
                    Add(&record, "level", String(item->level));
                    Add(&record, "source", String(item->source));
                    Add(&record, "message", String(item->message));
                    output.array.push_back(record);
                }
                Add(&result, "output", output);
                Add(&result, "next_cursor", has_next_cursor ?
                        String(FormatCursor("out", next_cursor)) : JsonValue::Null());
                response = AGENT_MakeJsonRpcResult(parsed.id, result);
            }
        }
    } else if (parsed.method == "debugger.execute_command") {
        std::string command;
        if (!GetString(parsed.params, "command", &command) || command.empty()) {
            response = InvalidParams(parsed.id, "debugger.execute_command requires a non-empty command string");
        } else if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before executing a debugger command", "TARGET_RUNNING", session);
        } else if (session->state != Impl::SessionState::Stopped) {
            response = SessionError(parsed.id, kErrorCommandRejected,
                                    "Debugger commands require a stopped target", "COMMAND_REJECTED", session);
        } else {
            const std::shared_ptr<Impl::AdapterOperation> operation(new Impl::AdapterOperation());
            if (SubmitEmulationCommandLocked(impl, [impl, operation, command](const std::uint64_t) {
                    AgentRuntime& adapter = *impl->runtime;
                    std::string adapter_error;
                    std::string raw_output;
                    const bool success = adapter.ExecuteDiagnosticCommand(command, &raw_output, &adapter_error);
                    {
                        std::lock_guard<std::mutex> operation_lock(operation->mutex);
                        operation->success = success;
                        operation->error = adapter_error;
                        operation->raw_output = raw_output;
                        operation->done = true;
                    }
                    operation->completed.notify_all();
                }) == 0) {
                response = Error(parsed.id, kErrorCommandRejected,
                                 "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
            } else {
                const JsonValue response_id = parsed.id;
                const std::string session_id = session->id;
                Impl::DeferredRequest pending;
                pending.request = parsed;
                pending.fingerprint = parsed.fingerprint;
                pending.wait = [operation](const std::uint32_t timeout_ms) {
                    std::unique_lock<std::mutex> operation_lock(operation->mutex);
                    return operation->completed.wait_for(operation_lock, std::chrono::milliseconds(timeout_ms),
                                                         [operation]() { return operation->done; });
                };
                pending.finish = [impl, session_id, response_id, operation]() {
                    if (!operation->success) {
                        return Error(response_id, kErrorCommandRejected,
                                     operation->error.empty() ? "Debugger command was rejected" : operation->error,
                                     "COMMAND_REJECTED");
                    }
                    if (!impl->session || impl->session->id != session_id)
                        return Error(response_id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
                    Impl::Session& active = *impl->session;
                    AppendOutput(&active, "debugger.command", operation->raw_output);
                    const DebuggerOutputParseResult parsed_output =
                            AGENT_ParseDebuggerRegisterOutput(operation->raw_output);
                    JsonValue result = SessionResult(active);
                    Add(&result, "accepted", JsonValue::Bool(true));
                    Add(&result, "raw_output", String(operation->raw_output));
                    Add(&result, "parse_status", String(parsed_output.complete ? "complete" : "failed"));
                    if (parsed_output.complete) {
                        JsonValue registers = Object();
                        for (std::map<std::string, std::string>::const_iterator item = parsed_output.registers.begin();
                             item != parsed_output.registers.end(); ++item) {
                            Add(&registers, item->first.c_str(), String(item->second));
                        }
                        Add(&result, "parsed_registers", registers);
                    } else {
                        Add(&result, "unparsed_output", String(parsed_output.unparsed_output));
                    }
                    return AGENT_MakeJsonRpcResult(response_id, result);
                };
                if (parsed.has_id && parsed.id.type != JsonType::Null)
                    session->deferred_requests[parsed.id_key] = pending;

                lock.unlock();
                const bool completed = pending.wait(impl->config.request_timeout_ms);
                lock.lock();
                if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                    return response;
                if (!completed) {
                    if (parsed.has_id && parsed.id.type != JsonType::Null)
                        cache_response = false;
                    response = Error(parsed.id, kErrorOperationTimeout,
                                     "Timed out executing debugger command", "OPERATION_TIMEOUT");
                } else if (parsed.has_id && parsed.id.type != JsonType::Null) {
                    std::map<std::string, Impl::DeferredRequest>::iterator deferred =
                            session->deferred_requests.find(parsed.id_key);
                    response = deferred->second.finish();
                    session->deferred_requests.erase(deferred);
                } else {
                    response = pending.finish();
                }
            }
        }
    } else if (parsed.method == "trace.start") {
        std::string detail;
        const JsonValue* instruction_count_value = parsed.params.Find("instruction_count");
        std::uint32_t instruction_count = 0;
        if (!GetString(parsed.params, "detail", &detail) || instruction_count_value == NULL ||
            !GetUnsignedInteger(*instruction_count_value, &instruction_count) || instruction_count == 0) {
            response = InvalidParams(parsed.id,
                                     "trace.start requires detail and a positive integer instruction_count");
        } else if (detail != "short" && detail != "normal" && detail != "long" && detail != "csip") {
            response = InvalidParams(parsed.id, "trace.start detail must be short, normal, long, or csip");
        } else if (instruction_count > impl->config.max_trace_events) {
            response = Error(parsed.id, kErrorRequestTooLarge,
                             "trace.start instruction_count exceeds max_trace_events", "REQUEST_TOO_LARGE");
        } else if (session->state == Impl::SessionState::Running) {
            response = SessionError(parsed.id, kErrorTargetRunning,
                                    "Target must be stopped before starting a trace", "TARGET_RUNNING", session);
        } else if (session->state != Impl::SessionState::Stopped) {
            response = SessionError(parsed.id, kErrorCommandRejected,
                                    "trace.start requires a stopped target", "COMMAND_REJECTED", session);
        } else if (session->trace.IsActive()) {
            response = Error(parsed.id, kErrorCommandRejected, "A CPU trace is already active", "COMMAND_REJECTED");
        } else {
            const std::shared_ptr<Impl::AdapterOperation> operation(new Impl::AdapterOperation());
            if (SubmitEmulationCommandLocked(impl, [impl, operation, detail, instruction_count](const std::uint64_t) {
                    AgentRuntime& adapter = *impl->runtime;
                    std::string adapter_error;
                    const bool success = adapter.StartTrace(detail, instruction_count, &adapter_error);
                    {
                        std::lock_guard<std::mutex> operation_lock(operation->mutex);
                        operation->success = success;
                        operation->error = adapter_error;
                        operation->done = true;
                    }
                    operation->completed.notify_all();
                }) == 0) {
                    response = Error(parsed.id, kErrorCommandRejected,
                                     "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
                } else {
                    const JsonValue response_id = parsed.id;
                    const std::string session_id = session->id;
                    Impl::DeferredRequest pending;
                    pending.request = parsed;
                    pending.fingerprint = parsed.fingerprint;
                    pending.wait = [operation](const std::uint32_t timeout_ms) {
                        std::unique_lock<std::mutex> operation_lock(operation->mutex);
                        return operation->completed.wait_for(operation_lock, std::chrono::milliseconds(timeout_ms),
                                                             [operation]() { return operation->done; });
                    };
                    pending.finish = [impl, session_id, response_id, operation, detail, instruction_count]() {
                        if (!operation->success) {
                            return Error(response_id, kErrorCommandRejected,
                                         operation->error.empty() ? "CPU trace was rejected" : operation->error,
                                         "COMMAND_REJECTED");
                        }
                        if (!impl->session || impl->session->id != session_id)
                            return Error(response_id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
                        Impl::Session& active = *impl->session;
                        active.trace.Begin(detail);
                        JsonValue result = SessionResult(active);
                        Add(&result, "detail", String(detail));
                        Add(&result, "instruction_count", Number(instruction_count));
                        Add(&result, "active", JsonValue::Bool(true));
                        return AGENT_MakeJsonRpcResult(response_id, result);
                    };
                    if (parsed.has_id && parsed.id.type != JsonType::Null)
                        session->deferred_requests[parsed.id_key] = pending;

                    lock.unlock();
                    const bool completed = pending.wait(impl->config.request_timeout_ms);
                    lock.lock();
                    if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                        return response;
                    if (!completed) {
                        if (parsed.has_id && parsed.id.type != JsonType::Null)
                            cache_response = false;
                        response = Error(parsed.id, kErrorOperationTimeout,
                                         "Timed out starting CPU trace", "OPERATION_TIMEOUT");
                    } else if (parsed.has_id && parsed.id.type != JsonType::Null) {
                        std::map<std::string, Impl::DeferredRequest>::iterator deferred =
                                session->deferred_requests.find(parsed.id_key);
                        response = deferred->second.finish();
                        session->deferred_requests.erase(deferred);
                    } else {
                        response = pending.finish();
                    }
                }
        }
    } else if (parsed.method == "trace.read") {
        const JsonValue* limit_value = parsed.params.Find("limit");
        bool has_cursor = false;
        std::uint64_t cursor = 0;
        std::uint32_t limit = 0;
        if (!ParseCursor(parsed.params.Find("cursor"), "trace", &has_cursor, &cursor) ||
            limit_value == NULL || !GetUnsignedInteger(*limit_value, &limit) || limit == 0) {
            response = InvalidParams(parsed.id,
                                     "trace.read requires cursor=null|trace-N and a positive integer limit");
        } else if (session->trace.Detail().empty()) {
            response = Error(parsed.id, kErrorCommandRejected, "No CPU trace has been started", "COMMAND_REJECTED");
        } else {
            const std::shared_ptr<Impl::AdapterOperation> operation(new Impl::AdapterOperation());
            const std::string session_id = session->id;
            if (SubmitEmulationCommandLocked(impl, [impl, operation](const std::uint64_t) {
                    AgentRuntime& adapter = *impl->runtime;
                    std::string adapter_error;
                    std::vector<TraceSample> samples;
                    bool active = false;
                    const bool success = adapter.ReadTrace(&samples, &active, &adapter_error);
                    {
                        std::lock_guard<std::mutex> operation_lock(operation->mutex);
                        operation->success = success;
                        operation->error = adapter_error;
                        operation->trace_samples.swap(samples);
                        operation->trace_active = active;
                        operation->done = true;
                    }
                    operation->completed.notify_all();
                }) == 0) {
                response = Error(parsed.id, kErrorCommandRejected,
                                 "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
            } else {
                std::unique_lock<std::mutex> operation_lock(operation->mutex);
                lock.unlock();
                const bool completed = operation->completed.wait_for(operation_lock,
                        std::chrono::milliseconds(impl->config.request_timeout_ms),
                        [operation]() { return operation->done; });
                lock.lock();
                if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                    return response;
                if (!completed) {
                    response = Error(parsed.id, kErrorOperationTimeout,
                                     "Timed out reading CPU trace", "OPERATION_TIMEOUT");
                } else if (!operation->success) {
                    response = Error(parsed.id, kErrorCommandRejected,
                                     operation->error.empty() ? "Unable to read CPU trace" : operation->error,
                                     "COMMAND_REJECTED");
                } else {
                    session->trace.Merge(operation->trace_samples);
                    if (!operation->trace_active)
                        session->trace.Stop();
                    TracePage page;
                    bool cursor_expired = false;
                    if (!session->trace.Read(has_cursor, cursor, limit, &page, &cursor_expired)) {
                        response = Error(parsed.id, kErrorCursorExpired,
                                         "trace cursor is no longer available", "CURSOR_EXPIRED");
                    } else {
                        JsonValue result = SessionResult(*session);
                        Add(&result, "active", JsonValue::Bool(session->trace.IsActive()));
                        JsonValue events = JsonValue::Array();
                        for (std::vector<TraceEvent>::const_iterator item = page.events.begin();
                             item != page.events.end(); ++item) {
                            events.array.push_back(TraceEventResult(*item, session->trace.Detail()));
                        }
                        Add(&result, "events", events);
                        Add(&result, "next_cursor", page.has_next_cursor ?
                                String(FormatCursor("trace", page.next_cursor)) : JsonValue::Null());
                        response = AGENT_MakeJsonRpcResult(parsed.id, result);
                    }
                }
            }
        }
    } else if (parsed.method == "trace.stop") {
        if (session->trace.Detail().empty()) {
            response = Error(parsed.id, kErrorCommandRejected, "No CPU trace has been started", "COMMAND_REJECTED");
        } else {
            const std::shared_ptr<Impl::AdapterOperation> operation(new Impl::AdapterOperation());
            if (SubmitEmulationCommandLocked(impl, [impl, operation](const std::uint64_t) {
                    AgentRuntime& adapter = *impl->runtime;
                    std::string adapter_error;
                    std::vector<TraceSample> samples;
                    bool active = false;
                    bool success = adapter.ReadTrace(&samples, &active, &adapter_error);
                    std::size_t event_count = samples.size();
                    if (success && active)
                        success = adapter.StopTrace(&event_count, &adapter_error);
                    if (success)
                        success = adapter.ReadTrace(&samples, &active, &adapter_error);
                    {
                        std::lock_guard<std::mutex> operation_lock(operation->mutex);
                        operation->success = success;
                        operation->error = adapter_error;
                        operation->trace_samples.swap(samples);
                        operation->trace_active = active;
                        operation->trace_event_count = event_count;
                        operation->done = true;
                    }
                    operation->completed.notify_all();
                }) == 0) {
                    response = Error(parsed.id, kErrorCommandRejected,
                                     "Emulation-thread bridge is unavailable", "COMMAND_REJECTED");
                } else {
                    const JsonValue response_id = parsed.id;
                    const std::string session_id = session->id;
                    Impl::DeferredRequest pending;
                    pending.request = parsed;
                    pending.fingerprint = parsed.fingerprint;
                    pending.wait = [operation](const std::uint32_t timeout_ms) {
                        std::unique_lock<std::mutex> operation_lock(operation->mutex);
                        return operation->completed.wait_for(operation_lock, std::chrono::milliseconds(timeout_ms),
                                                             [operation]() { return operation->done; });
                    };
                    pending.finish = [impl, session_id, response_id, operation]() {
                        if (!operation->success) {
                            return Error(response_id, kErrorCommandRejected,
                                         operation->error.empty() ? "Unable to stop CPU trace" : operation->error,
                                         "COMMAND_REJECTED");
                        }
                        if (!impl->session || impl->session->id != session_id)
                            return Error(response_id, kErrorSessionNotFound, "Session was not found", "SESSION_NOT_FOUND");
                        Impl::Session& active = *impl->session;
                        active.trace.Merge(operation->trace_samples);
                        active.trace.Stop();
                        JsonValue result = SessionResult(active);
                        Add(&result, "active", JsonValue::Bool(false));
                        Add(&result, "event_count", Number(active.trace.EventCount()));
                        return AGENT_MakeJsonRpcResult(response_id, result);
                    };
                    if (parsed.has_id && parsed.id.type != JsonType::Null)
                        session->deferred_requests[parsed.id_key] = pending;

                    lock.unlock();
                    const bool completed = pending.wait(impl->config.request_timeout_ms);
                    lock.lock();
                    if (!RebindSessionAfterWait(impl, session_id, &session, &response, parsed.id))
                        return response;
                    if (!completed) {
                        if (parsed.has_id && parsed.id.type != JsonType::Null)
                            cache_response = false;
                        response = Error(parsed.id, kErrorOperationTimeout,
                                         "Timed out stopping CPU trace", "OPERATION_TIMEOUT");
                    } else if (parsed.has_id && parsed.id.type != JsonType::Null) {
                        std::map<std::string, Impl::DeferredRequest>::iterator deferred =
                                session->deferred_requests.find(parsed.id_key);
                        response = deferred->second.finish();
                        session->deferred_requests.erase(deferred);
                    } else {
                        response = pending.finish();
                    }
                }
        }
    } else {
        response = AGENT_MakeJsonRpcError(parsed.id, -32601, "Method not found");
    }

    if (cache_response)
        CacheResponse(session, parsed, response);
    return response;
}

void AgentServer::StartTargetOnEmulationThread(const std::shared_ptr<Impl>& impl,
                                               const std::string& session_id,
                                               const std::string& target_command,
                                               const std::vector<std::string>& target_arguments,
                                               const std::string& workdir)
{
    AgentRuntime& adapter = *impl->runtime;
    if (!adapter.IsReadyForTargetStart()) {
        {
            std::lock_guard<std::mutex> command_lock(impl->mutex);
            if (impl->stopping || !impl->session || impl->session->id != session_id ||
                impl->session->state != Impl::SessionState::Starting)
                return;
            if (std::chrono::steady_clock::now() >= impl->session->startup_deadline) {
                impl->session->state = Impl::SessionState::Failed;
                impl->session->failure_message = "Timed out waiting for the debugger shell to become ready";
                impl->state_changed.notify_all();
                return;
            }
            impl->session->startup_phase = "waiting_for_ready";
            ++impl->session->startup_retry_count;
        }
        if (SubmitEmulationCommandAfter(impl, 10,
                                        [impl, session_id, target_command, target_arguments, workdir](const std::uint64_t) {
                StartTargetOnEmulationThread(impl, session_id, target_command, target_arguments, workdir);
            }) != 0) {
            return;
        }

        std::lock_guard<std::mutex> command_lock(impl->mutex);
        if (impl->session && impl->session->id == session_id &&
            impl->session->state == Impl::SessionState::Starting) {
            impl->session->state = Impl::SessionState::Failed;
            impl->session->failure_message = "Emulation-thread bridge is unavailable while waiting for the debugger shell";
            impl->state_changed.notify_all();
        }
        return;
    }

    {
        std::lock_guard<std::mutex> command_lock(impl->mutex);
        if (impl->stopping || !impl->session || impl->session->id != session_id ||
            impl->session->state != Impl::SessionState::Starting)
            return;
        if (std::chrono::steady_clock::now() >= impl->session->startup_deadline) {
            impl->session->state = Impl::SessionState::Failed;
            impl->session->failure_message = "Timed out waiting for target entry breakpoint";
            impl->state_changed.notify_all();
            return;
        }
        impl->session->startup_phase = "launching";
        impl->session->startup_entry_breakpoint_baseline = adapter.EntryBreakpointSequence();
        impl->session->startup_entry_breakpoint_created = false;
    }

    std::string launch_error;
    if (adapter.StartTargetAtEntry(target_command, target_arguments, workdir, &launch_error)) {
        std::lock_guard<std::mutex> command_lock(impl->mutex);
        if (impl->session && impl->session->id == session_id &&
            impl->session->state == Impl::SessionState::Starting) {
            impl->session->startup_phase = "launch_returned";
            impl->session->startup_entry_breakpoint_created =
                    adapter.EntryBreakpointSequence() > impl->session->startup_entry_breakpoint_baseline;
        }
        return;
    }

    std::lock_guard<std::mutex> command_lock(impl->mutex);
    if (impl->session && impl->session->id == session_id &&
        impl->session->state == Impl::SessionState::Starting) {
        impl->session->state = Impl::SessionState::Failed;
        impl->session->failure_message = launch_error;
        impl->state_changed.notify_all();
    }
}

void AgentServer::CompleteTargetTerminationOnEmulationThread(const std::shared_ptr<Impl>& impl,
                                                             const std::string& session_id,
                                                             const std::string& operation_id)
{
    AgentRuntime& adapter = *impl->runtime;
    if (!adapter.IsReadyForTargetStart()) {
        {
            std::lock_guard<std::mutex> command_lock(impl->mutex);
            if (impl->stopping || !impl->session || impl->session->id != session_id)
                return;
            Impl::Session& active = *impl->session;
            std::map<std::string, Impl::Operation>::iterator pending = active.operations.find(operation_id);
            if (pending == active.operations.end() || pending->second.complete)
                return;
            if (std::chrono::steady_clock::now() >= active.termination_deadline) {
                active.state = Impl::SessionState::Failed;
                active.failure_message = "Timed out waiting for the debugger shell after target termination";
                active.last_stop_kind = "fault";
                pending->second.terminal_state = Impl::SessionState::Failed;
                pending->second.stop_kind = "fault";
                pending->second.complete = true;
                ++active.state_revision;
                impl->state_changed.notify_all();
                return;
            }
            ++active.termination_retry_count;
        }
        if (SubmitEmulationCommandAfter(impl, 10, [impl, session_id, operation_id](const std::uint64_t) {
                CompleteTargetTerminationOnEmulationThread(impl, session_id, operation_id);
            }) != 0)
            return;

        std::lock_guard<std::mutex> command_lock(impl->mutex);
        if (impl->session && impl->session->id == session_id) {
            Impl::Session& active = *impl->session;
            std::map<std::string, Impl::Operation>::iterator pending = active.operations.find(operation_id);
            if (pending != active.operations.end() && !pending->second.complete) {
                active.state = Impl::SessionState::Failed;
                active.failure_message = "Emulation-thread bridge is unavailable while completing target termination";
                active.last_stop_kind = "fault";
                pending->second.terminal_state = Impl::SessionState::Failed;
                pending->second.stop_kind = "fault";
                pending->second.complete = true;
                ++active.state_revision;
                impl->state_changed.notify_all();
            }
        }
        return;
    }

    std::lock_guard<std::mutex> command_lock(impl->mutex);
    if (!impl->session || impl->session->id != session_id)
        return;
    Impl::Session& active = *impl->session;
    if (active.operations.find(operation_id) == active.operations.end())
        return;

    active.state = Impl::SessionState::Exited;
    active.trace.Stop();
    active.last_stop_kind = "program_exit";
    active.last_stop_breakpoint_id.clear();
    active.has_last_stop_breakpoint_address = false;
    ++active.state_revision;
    for (std::map<std::string, Impl::Operation>::iterator item = active.operations.begin(); item != active.operations.end(); ++item) {
        if (!item->second.complete) {
            item->second.terminal_state = Impl::SessionState::Exited;
            item->second.stop_kind = "program_exit";
            item->second.complete = true;
        }
    }
    impl->state_changed.notify_all();
}

void AgentServer::OnDebuggerStopped(const std::shared_ptr<Impl>& impl,
                                    const std::uint64_t generation,
                                    const std::uint16_t segment,
                                    const std::uint32_t instruction_pointer)
{
    EmulationLease lease(impl, generation);
    if (!lease.IsActive())
        return;
    AgentRuntime& adapter = *impl->runtime;
    const std::uintptr_t native_breakpoint = adapter.ConsumeLastBreakpointHandle();
    std::vector<TraceSample> trace_samples;
    bool native_trace_active = false;
    std::string trace_error;
    bool should_read_trace = false;
    {
        std::lock_guard<std::mutex> state_lock(impl->mutex);
        should_read_trace = !impl->stopping && impl->session &&
                (impl->session->state == Impl::SessionState::Starting ||
                 impl->session->state == Impl::SessionState::Running) &&
                impl->session->trace.IsActive();
    }
    const bool trace_read = should_read_trace &&
            adapter.ReadTrace(&trace_samples, &native_trace_active, &trace_error);
    std::lock_guard<std::mutex> lock(impl->mutex);
    if (impl->stopping || !impl->session)
        return;

    if (impl->session->state != Impl::SessionState::Starting &&
        impl->session->state != Impl::SessionState::Running)
        return;

    const bool startup = impl->session->state == Impl::SessionState::Starting;
    const bool trace_completed = impl->session->trace.IsActive() && trace_read && !native_trace_active;
    if (impl->session->trace.IsActive() && trace_read) {
        impl->session->trace.Merge(trace_samples);
        if (!native_trace_active)
            impl->session->trace.Stop();
    }
    impl->session->state = Impl::SessionState::Stopped;
    impl->session->last_stop_kind = startup ? "startup" :
            (native_breakpoint != 0 ? "breakpoint" :
             (!impl->session->pending_stop_kind.empty() ? impl->session->pending_stop_kind :
              (trace_completed ? "pause" : "breakpoint")));
    impl->session->last_stop_segment = segment;
    impl->session->last_stop_instruction_pointer = instruction_pointer;
    impl->session->last_stop_breakpoint_id.clear();
    impl->session->has_last_stop_breakpoint_address = false;
    if (!startup && impl->session->last_stop_kind == "breakpoint" && native_breakpoint != 0) {
        for (std::map<std::string, Impl::Breakpoint>::iterator item = impl->session->breakpoints.begin();
             item != impl->session->breakpoints.end(); ++item) {
            if (item->second.native.handle != native_breakpoint)
                continue;
            impl->session->last_stop_breakpoint_id = item->second.id;
            impl->session->last_stop_breakpoint_address = item->second.native.address;
            impl->session->has_last_stop_breakpoint_address = true;
            if (item->second.native.once)
                impl->session->breakpoints.erase(item);
            break;
        }
    }
    if (startup)
        impl->session->state_revision = 1;
    else
        ++impl->session->state_revision;
    for (std::map<std::string, Impl::Operation>::iterator operation = impl->session->operations.begin();
         operation != impl->session->operations.end(); ++operation) {
        if (!operation->second.complete) {
            operation->second.terminal_state = Impl::SessionState::Stopped;
            operation->second.stop_kind = impl->session->last_stop_kind;
            operation->second.complete = true;
        }
    }
    impl->session->pending_stop_kind.clear();
    impl->state_changed.notify_all();
}

bool AgentServer::RunProtocolSelfTest(std::string* error)
{
    if (error == NULL)
        return false;
    error->clear();

    AgentConfig config;
    {
        std::lock_guard<std::mutex> lock(impl->mutex);
        if (!impl->started) {
            *error = "Agent server is not started";
            return false;
        }
        config = impl->config;
    }

    const std::string invalid = HandleJsonRpc("{\"method\":\"agent.capabilities\"}");
    if (invalid.find("\"code\":-32600") == std::string::npos) {
        *error = "Missing-jsonrpc request was not rejected";
        return false;
    }
    const std::string unknown = HandleJsonRpc("{\"jsonrpc\":\"2.0\",\"id\":\"unknown\",\"method\":\"unknown.method\"}");
    if (unknown.find("\"code\":-32601") == std::string::npos) {
        *error = "Unknown method was not rejected";
        return false;
    }
    const std::string wrong_type = HandleJsonRpc("{\"jsonrpc\":\"2.0\",\"id\":\"wrong-type\",\"method\":\"agent.capabilities\",\"params\":[]}");
    if (wrong_type.find("\"code\":-32600") == std::string::npos) {
        *error = "Invalid params type was not rejected";
        return false;
    }
    const std::string oversized = HandleJsonRpc(std::string(config.max_message_bytes + 1, 'x'));
    if (oversized.find("REQUEST_TOO_LARGE") == std::string::npos) {
        *error = "Oversized request was not rejected";
        return false;
    }
    const std::string capabilities = HandleJsonRpc("{\"jsonrpc\":\"2.0\",\"id\":\"cap\",\"method\":\"agent.capabilities\"}");
    if (capabilities.find("\"debugger\":true") == std::string::npos ||
        capabilities.find("\"segmented\"") == std::string::npos ||
        capabilities.find("\"screen_text\":true") == std::string::npos) {
        *error = "Capabilities response is incomplete";
        return false;
    }
    // Guest I/O parameter validation happens before anything reaches the emulation thread.
    const std::string bad_key = HandleJsonRpc("{\"jsonrpc\":\"2.0\",\"id\":\"bad-key\",\"method\":\"input.key\",\"params\":{\"key\":\"no-such-key\"}}");
    if (bad_key.find("\"code\":-32602") == std::string::npos) {
        *error = "Unknown key name was not rejected";
        return false;
    }
    const std::string bad_combo = HandleJsonRpc("{\"jsonrpc\":\"2.0\",\"id\":\"bad-combo\",\"method\":\"input.keys\",\"params\":{\"keys\":[\"ctrl+nope\"]}}");
    if (bad_combo.find("\"code\":-32602") == std::string::npos) {
        *error = "Unknown key in a combo was not rejected";
        return false;
    }
    const std::string bad_text = HandleJsonRpc("{\"jsonrpc\":\"2.0\",\"id\":\"bad-text\",\"method\":\"input.type_text\",\"params\":{\"text\":\"\xC3\xA9\"}}");
    if (bad_text.find("\"code\":-32602") == std::string::npos) {
        *error = "Untypeable text was not rejected";
        return false;
    }
    const std::string bad_mouse = HandleJsonRpc("{\"jsonrpc\":\"2.0\",\"id\":\"bad-mouse\",\"method\":\"input.mouse\",\"params\":{\"x\":0.5}}");
    if (bad_mouse.find("\"code\":-32602") == std::string::npos) {
        *error = "Mouse x without y was not rejected";
        return false;
    }
    const std::string bad_slot = HandleJsonRpc("{\"jsonrpc\":\"2.0\",\"id\":\"bad-slot\",\"method\":\"state.save\",\"params\":{}}");
    if (bad_slot.find("\"code\":-32602") == std::string::npos) {
        *error = "state.save without slot was not rejected";
        return false;
    }
#ifdef C_HEAVY_DEBUG
    if (capabilities.find("\"cpu\":true") == std::string::npos) {
        *error = "Heavy-debug build did not advertise CPU trace support";
        return false;
    }
#else
    if (capabilities.find("\"cpu\":false") == std::string::npos) {
        *error = "Non-heavy build did not disable CPU trace capability";
        return false;
    }
    const std::string trace = HandleJsonRpc("{\"jsonrpc\":\"2.0\",\"id\":\"trace\",\"method\":\"trace.start\",\"params\":{}}");
    if (trace.find("CAPABILITY_UNAVAILABLE") == std::string::npos) {
        *error = "Non-heavy build did not reject CPU trace";
        return false;
    }
#endif
    return true;
}

} // namespace dosbox_agent
#endif // defined(C_DEBUG) && defined(C_DOSBOX_AGENT)
