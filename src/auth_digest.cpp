#include "auth_digest.hpp"
#include "user_info.hpp"
#include "userver/logging/log.hpp"
#include "userver/server/handlers/auth/auth_checker_settings.hpp"
#include "userver/server/handlers/auth/auth_digest_checker_base.hpp"
#include "userver/storages/postgres/component.hpp"
#include "userver/storages/postgres/io/row_types.hpp"
#include "userver/storages/postgres/postgres_fwd.hpp"
#include "userver/storages/postgres/query.hpp"
#include "userver/storages/postgres/result_set.hpp"

#include <algorithm>
#include <optional>
#include <userver/http/common_headers.hpp>
#include <userver/server/handlers/auth/auth_digest_checker_component.hpp>
#include <userver/server/handlers/auth/auth_digest_checker_stand_alone.hpp>

namespace samples::pg {

using UserData = server::handlers::auth::UserData;

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
                                                      std::move(realm)),
        pg_cluster_(
            context
                .FindComponent<userver::components::Postgres>("auth-database")
                .GetCluster()) {}

  std::optional<HA1> GetHA1(const std::string& username) const override;

  std::optional<UserData> GetUserData(
      const std::string& username) const override;

  void SetUserData(const std::string& username,
                   UserData user_data) const override;

 private:
  userver::storages::postgres::ClusterPtr pg_cluster_;

  const storages::postgres::Query kSelectUser{
      "SELECT username, nonce, timestamp, nonce_count, ha1 "
      "FROM auth_schema.users WHERE username=$1",
      storages::postgres::Query::Name{"select_user"}};

  const storages::postgres::Query kSelectHA1{
      "SELECT ha1 FROM auth_schema.users WHERE username=$1",
      storages::postgres::Query::Name{"select_ha1"}};

  const storages::postgres::Query kUpdateUser{
      "UPDATE auth_schema.users "
      "SET nonce=$1, timestamp=$2, nonce_count=$3 "
      "WHERE username=$4",
      storages::postgres::Query::Name{"update_user"}};
};

std::optional<AuthCheckerDigest::HA1> AuthCheckerDigest::GetHA1(
    const std::string& username) const {
  storages::postgres::ResultSet res = pg_cluster_->Execute(
      storages::postgres::ClusterHostType::kSlave, kSelectHA1, username);

  if (res.IsEmpty()) return std::nullopt;

  return AuthCheckerDigest::HA1{res.AsSingleRow<std::string>()};
}

std::optional<UserData> AuthCheckerDigest::GetUserData(
    const std::string& username) const {
  storages::postgres::ResultSet res = pg_cluster_->Execute(
      storages::postgres::ClusterHostType::kSlave, kSelectUser, username);

  if (res.IsEmpty()) return std::nullopt;

  auto userDbInfo = res.AsSingleRow<UserDbInfo>(userver::storages::postgres::kRowTag);
  return UserData(userDbInfo.nonce, userDbInfo.timestamp,
                  userDbInfo.nonce_count);
}

void AuthCheckerDigest::SetUserData(const std::string& username,
                                    UserData user_data) const {
  pg_cluster_->Execute(storages::postgres::ClusterHostType::kMaster, kUpdateUser,
                       user_data.nonce, user_data.timestamp, static_cast<int>(user_data.nonce_count), username);
}

server::handlers::auth::AuthCheckerBasePtr CheckerFactory::operator()(
    const ::components::ComponentContext& context,
    const server::handlers::auth::HandlerAuthConfig& auth_config,
    const server::handlers::auth::AuthCheckerSettings&) const {
  const auto& digest_auth_settings =
      context.FindComponent<component::AuthDigestCheckerComponent>()
          .GetSettings();
          
  return std::make_shared<AuthCheckerDigest>(
      digest_auth_settings, auth_config["realm"].As<std::string>({}), context);
}

}  // namespace samples::pg
