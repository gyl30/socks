#include "trace_web_dashboard_page.h"

namespace relay
{

std::string build_trace_dashboard_page_body()
{
    return
#include "trace_web_dashboard_page.html.inc"
}

}    // namespace relay
