#ifndef STOP_DISPATCH_H
#define STOP_DISPATCH_H

#include <utility>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

namespace mux::detail
{

template <typename Fn>
void dispatch_cleanup_or_run_inline(boost::asio::io_context& io_context, Fn&& fn)
{
    boost::asio::post(io_context, std::forward<Fn>(fn));
}

}    // namespace mux::detail

#endif
