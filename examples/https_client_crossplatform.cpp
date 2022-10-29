//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>


#include <iostream>
#include <regex>
#include <string>

namespace beast = boost::beast;      // from <boost/beast.hpp>
namespace http = beast::http;        // from <boost/beast/http.hpp>
namespace net = boost::asio;         // from <boost/asio.hpp>

using tcp = boost::asio::ip::tcp;    // from <boost/asio/ip/tcp.hpp>

#ifdef USE_WINTLS
#include <boost/wintls.hpp>
namespace ssl = boost::wintls;

ssl::context get_context() {
  // The SSL context is required, and holds certificates
  ssl::context ctx{boost::wintls::method::system_default};

  // Use the operating systems default certificates for verification
  ctx.use_default_certificates(true);

  // Verify the remote server's certificate
  ctx.verify_server_certificate(true);

  return ctx;
}

template<typename Stream>
void setup_stream(ssl::stream<Stream>& stream, const std::string& host) {
  // Set SNI hostname (many hosts need this to handshake successfully)
  stream.set_server_hostname(host);

  // Enable Check whether the Server Certificate was revoked
  stream.set_certificate_revocation_check(true);
}

constexpr auto handshake_type_client = ssl::handshake_type::client;

#else
#include <boost/asio/ssl.hpp>
namespace ssl = boost::asio::ssl;

ssl::context get_context() {
  // The SSL context is required, and holds certificates
  ssl::context ctx{ssl::context::tlsv12_client};

  // Use OpenSSLs default certificates for verification
  ctx.set_default_verify_paths();

  // Verify the remote server's certificate
  ctx.set_verify_mode(ssl::context::verify_peer | ssl::context::verify_fail_if_no_peer_cert);

  return ctx;
}

template<typename Stream>
void setup_stream(ssl::stream<Stream>& stream, const std::string& host) {
  // Set SNI Hostname (many hosts need this to handshake successfully)
  if (!SSL_set_tlsext_host_name(stream.native_handle(), host.data())) {
    throw boost::system::error_code {static_cast<int>(ERR_get_error()), net::error::get_ssl_category()};
  }
  // Set OpenSSL parameters for Certificate verification
  auto* param = SSL_get0_param(stream.native_handle());
  // Enable host name verification
  X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
  if (!X509_VERIFY_PARAM_set1_host(param, host.data(), host.size())) {
    throw boost::system::error_code {static_cast<int>(ERR_get_error()), net::error::get_ssl_category()};
  }
  // Enable some revocation check
  // #TODO: Remove or add some comment that OpenSSL will not do any effort to get revocation info.
  if (!X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK)) {
    throw boost::system::error_code{static_cast<int>(ERR_get_error()), net::error::get_ssl_category()};
  }
}

constexpr auto handshake_type_client = ssl::stream_base::handshake_type::client;

#endif

//------------------------------------------------------------------------------

// Performs an HTTP GET and prints the response
int main(int argc, char** argv) {
  try {
    // Exactly one command line argument required - the HTTPS URL
    if(argc != 2) {
      std::cerr << "Usage: " << argv[0] << " [HTTPS_URL]\n\n";
      std::cerr << "Example: " << argv[0] << " https://www.boost.org/LICENSE_1_0.txt\n";
      return EXIT_FAILURE;
    }

    const std::string url{argv[1]};

    // Very basic URL matching. Not a full URL validator.
    std::regex re("https://([^/$:]+):?([^/$]*)(/?.*)");
    std::smatch what;
    if(!regex_match(url, what, re)) {
      std::cerr << "Invalid or unsupported URL: " << url << "\n";
      return EXIT_FAILURE;
    }

    // Get the relevant parts of the URL
    const std::string host = std::string(what[1]);
    // Use default HTTPS port (443) if not specified
    const std::string port = what[2].length() > 0 ? what[2].str() : "443";
    // Use default path ('/') if not specified
    const std::string path = what[3].length() > 0 ? what[3].str() : "/";

    // Use HTTP/1.1
    const int version = 11;

    // The io_context is required for all I/O
    net::io_context ioc;

    auto ctx = get_context();

    // Construct the TLS stream with the parameters from the context
    ssl::stream<beast::tcp_stream> stream(ioc, ctx);

    setup_stream(stream, host);

    // Look up the domain name
    tcp::resolver resolver(ioc);
    auto const results = resolver.resolve(host, port);

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(stream).connect(results);

    // Perform the TLS handshake
    stream.handshake(handshake_type_client);

    // Set up an HTTP GET request message
    http::request<http::string_body> req{http::verb::get, path, version};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Send the HTTP request to the remote host
    http::write(stream, req);

    // This buffer is used for reading and must be persisted
    beast::flat_buffer buffer;

    // Declare a container to hold the response
    http::response<http::dynamic_body> res;

    // Receive the HTTP response
    http::read(stream, buffer, res);

    // Write the message to standard out
    std::cout << res << std::endl;
    // Shutdown the TLS connection
    beast::error_code ec;
    stream.shutdown(ec);
    if (ec == net::error::eof) {
      // Rationale:
      // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
      ec = {};
    }
    if (ec)
      throw beast::system_error{ec};
  } catch(std::exception const& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
