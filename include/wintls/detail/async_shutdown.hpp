//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef WINTLS_DETAIL_ASYNC_SHUTDOWN_HPP
#define WINTLS_DETAIL_ASYNC_SHUTDOWN_HPP

#include <wintls/detail/config.hpp>
#include <wintls/detail/coroutine.hpp>
#include <wintls/detail/sspi_shutdown.hpp>

namespace wintls {
namespace detail {

template <typename NextLayer>
struct async_shutdown : net::coroutine {
  async_shutdown(NextLayer& next_layer, detail::sspi_shutdown& shutdown)
    : next_layer_(next_layer)
    , shutdown_(shutdown)
    , entry_count_(0) {
  }

  template <typename Self>
  void operator()(Self& self, wintls::error_code ec = {}, std::size_t size_written = 0) {
    if (ec) {
      self.complete(ec);
      return;
    }

    ++entry_count_;
    auto is_continuation = [this] {
      return entry_count_ > 1;
    };

    ec = shutdown_();

    WINTLS_ASIO_CORO_REENTER(*this) {
      if (!ec) {
        WINTLS_ASIO_CORO_YIELD {
          net::async_write(next_layer_, shutdown_.buffer(), std::move(self));
        }
        shutdown_.size_written(size_written);
        self.complete({});
        return;
      } else {
        if (!is_continuation()) {
          WINTLS_ASIO_CORO_YIELD {
            net::post(self.get_io_executor(), net::append(std::move(self), ec, size_written));
          }
        }
        self.complete(ec);
        return;
      }
    }
  }

private:
  NextLayer& next_layer_;
  detail::sspi_shutdown& shutdown_;
  int entry_count_;
};

} // namespace detail
} // namespace wintls

#endif // WINTLS_DETAIL_ASYNC_SHUTDOWN_HPP
