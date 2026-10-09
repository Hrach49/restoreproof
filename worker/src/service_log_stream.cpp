#include "service_log_stream.hpp"

#include <spdlog/logger.h>

#include <format>
#include <utility>

namespace rp {

LogLineWriter log_line_writer(std::shared_ptr<spdlog::logger> logger,
                              spdlog::level::level_enum level)
{
    return [logger = std::move(logger), level](std::string_view line) {
        if (logger) {
            logger->log(level, spdlog::string_view_t{line.data(), line.size()});
        }
    };
}

namespace detail {

LogLineBuffer::LogLineBuffer(LogLineWriter write, std::string_view run_id)
    : write_(std::move(write)), prefix_(std::format("[{}] ", run_id))
{
}

void LogLineBuffer::finish() noexcept
{
    take("\n");
}

LogLineBuffer::int_type LogLineBuffer::overflow(int_type ch)
{
    if (!traits_type::eq_int_type(ch, traits_type::eof())) {
        const char c = traits_type::to_char_type(ch);
        take({&c, 1});
    }
    return traits_type::not_eof(ch);
}

std::streamsize LogLineBuffer::xsputn(const char* text, std::streamsize count)
{
    take({text, static_cast<std::size_t>(count)});
    return count;
}

// Every piece is taken whatever becomes of it: a line that couldn't be kept
// or written is dropped, and the text after it goes on as its own lines.
void LogLineBuffer::take(std::string_view text) noexcept
{
    while (!text.empty()) {
        const std::size_t end = text.find('\n');
        const bool ended = end != std::string_view::npos;
        const std::string_view piece = text.substr(0, end);
        text = ended ? text.substr(end + 1) : std::string_view{};
        try {
            add(piece, ended);
        } catch (...) {
            pending_.clear();
        }
    }
}

void LogLineBuffer::add(std::string_view piece, bool ended)
{
    pending_.append(piece);
    if (!ended) {
        return;
    }
    std::string line = std::exchange(pending_, {});
    if (line.ends_with('\r')) {
        line.pop_back();
    }
    if (!line.empty() && write_) {
        write_(prefix_ + line);
    }
}

LogLineBufferHolder::LogLineBufferHolder(LogLineWriter write, std::string_view run_id)
    : buffer_(std::move(write), run_id)
{
}

} // namespace detail

LogLineStream::LogLineStream(std::shared_ptr<spdlog::logger> logger,
                             spdlog::level::level_enum level, std::string_view run_id)
    : LogLineStream(log_line_writer(std::move(logger), level), run_id)
{
}

LogLineStream::LogLineStream(LogLineWriter write, std::string_view run_id)
    : detail::LogLineBufferHolder(std::move(write), run_id), std::ostream(&buffer_)
{
}

LogLineStream::~LogLineStream()
{
    finish();
}

void LogLineStream::finish() noexcept
{
    buffer_.finish();
}

} // namespace rp
