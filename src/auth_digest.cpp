#include "auth_digest.hpp"
#include "user_info_cache.hpp"
#include "userver/logging/log.hpp"
#include "userver/server/handlers/auth/auth_checker_settings.hpp"
#include "userver/storages/postgres/postgres_fwd.hpp"

#include <algorithm>
#include <optional>
#include <userver/http/common_headers.hpp>
#include <userver/server/handlers/auth/auth_digest_checker_base.hpp>
#include <userver/server/handlers/auth/auth_digest_checker_component.hpp>

namespace samples::pg {

class AuthCheckerDigest final
    : public server::handlers::auth::AuthCheckerDigestBase {
 public:
  using AuthCheckResult = server::handlers::auth::AuthCheckResult;
  using AuthDigestSettings =
      userver::server::handlers::auth::AuthDigestSettings;

  AuthCheckerDigest(const AuthCache& auth_cache,
                    const AuthDigestSettings& digest_settings,
                    std::string realm,
                    const ::components::ComponentContext& context)
      : server::handlers::auth::AuthCheckerDigestBase(digest_settings,
                                                      std::move(realm)),
        auth_cache_(auth_cache) {}

  std::optional<HA1> GetHA1(const std::string& username) const override;

 private:
  const AuthCache& auth_cache_;
};

std::optional<AuthCheckerDigest::HA1> AuthCheckerDigest::GetHA1(
    const std::string& username) const {
  const auto cache_snapshot = auth_cache_.Get();

  auto finding_iterator = cache_snapshot->find(username);
  if (finding_iterator == cache_snapshot->end()) return std::nullopt;

  return HA1{finding_iterator->second.ha1};
}

server::handlers::auth::AuthCheckerBasePtr CheckerFactory::operator()(
    const ::components::ComponentContext& context,
    const server::handlers::auth::HandlerAuthConfig& auth_config,
    const server::handlers::auth::AuthCheckerSettings&) const {
  const auto& digest_auth_settings =
      context.FindComponent<component::AuthDigestCheckerComponent>()
          .GetSettings();
  return std::make_shared<AuthCheckerDigest>(
      context.FindComponent<AuthCache>(), digest_auth_settings,
      auth_config["realm"].As<std::string>({}), context);
}

}  // namespace samples::pg
