#include "auth_digest.hpp"
#include "user_info_cache.hpp"
#include "userver/logging/log.hpp"
#include "userver/server/handlers/auth/auth_checker_settings.hpp"
#include "userver/storages/postgres/postgres_fwd.hpp"

#include <algorithm>
#include <userver/http/common_headers.hpp>
#include <userver/server/handlers/auth/auth_digest_checker_base.hpp>

namespace samples::pg {

class AuthCheckerDigest final
    : public server::handlers::auth::AuthCheckerDigestBase {
 public:
  using AuthCheckResult = server::handlers::auth::AuthCheckResult;
  using AuthDigestSettings =
      userver::server::handlers::auth::AuthDigestSettings;

  AuthCheckerDigest(const AuthDigestSettings& digest_settings,
                    std::string realm,
                    const ::components::ComponentContext& context)
      : server::handlers::auth::AuthCheckerDigestBase(digest_settings,
                                                      std::move(realm)) {}

  HA1 GetHA1(std::string_view username) const override;
};

AuthCheckerDigest::HA1 AuthCheckerDigest::GetHA1(
    std::string_view username) const {
  return HA1{"dcd98b7102dd2f0e8b11d0f600bfb0c093"};
}

server::handlers::auth::AuthCheckerBasePtr CheckerFactory::operator()(
    const ::components::ComponentContext& context,
    const server::handlers::auth::HandlerAuthConfig& auth_config,
    const server::handlers::auth::AuthCheckerSettings&) const {
  const auto& digest_auth_settings = context.FindComponent<
      userver::server::handlers::auth::AuthDigestCheckerComponent>().GetSettings();
  return std::make_shared<AuthCheckerDigest>(digest_auth_settings, "registred_user@host.com",
                                             context);
}

}  // namespace samples::pg
