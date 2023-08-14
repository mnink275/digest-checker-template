#include "auth_digest.hpp"
#include "user_info_cache.hpp"
#include "userver/logging/log.hpp"

#include <userver/utest/using_namespace_userver.hpp>

#include <userver/clients/dns/component.hpp>
#include <userver/testsuite/testsuite_support.hpp>

#include <userver/components/minimal_server_component_list.hpp>
#include <userver/server/handlers/http_handler_base.hpp>
#include <userver/utils/daemon_run.hpp>

#include <userver/storages/postgres/cluster.hpp>
#include <userver/storages/postgres/component.hpp>

#include <userver/server/handlers/auth/auth_digest_checker_component.hpp>

namespace samples::pg {

class Hello final : public server::handlers::HttpHandlerBase {
 public:
  static constexpr std::string_view kName = "handler-hello";

  using HttpHandlerBase::HttpHandlerBase;

  std::string HandleRequestThrow(
      const server::http::HttpRequest&,
      server::request::RequestContext& ctx) const override {
    return "Hello world";
  }
};

}  // namespace samples::pg

int main(int argc, const char* const argv[]) {
  server::handlers::auth::RegisterAuthCheckerFactory(
      "digest", std::make_unique<samples::pg::CheckerFactory>());

  const auto component_list =
      components::MinimalServerComponentList()
          .Append<samples::pg::AuthCache>()
          .Append<components::Postgres>("auth-database")
          .Append<samples::pg::Hello>()
          .Append<components::TestsuiteSupport>()
          .Append<clients::dns::Component>()
          .Append<
              userver::server::handlers::auth::AuthDigestCheckerComponent>();
  return utils::DaemonMain(argc, argv, component_list);
}