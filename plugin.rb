# name: discourse-oidc-basic
# about: Generic OpenID Connect Plugin
# version: 0.1
# authors: Michał "rysiek" Woźniak

#require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :oidc_enabled

# based on:
# https://github.com/discourse/discourse/blob/master/lib/auth/open_id_authenticator.rb
# original code on GNU GPL v.2
class Auth::OpenIdConnectAuthenticator < Auth::Authenticator

    attr_reader :name, :identifier

    def initialize(name, identifier, opts = {})
        
        Rails.logger.debug "Auth::OpenIdConnectAuthenticator :: initialize"
        
        @name = name
        @identifier = identifier
        @opts = opts
    end

    def after_authenticate(auth_token)
        
        Rails.logger.debug "Auth::OpenIdConnectAuthenticator :: after_authenticate"
        
        result = Auth::Result.new

        data = auth_token[:info]
        identity_url = auth_token[:extra][:response].identity_url
        result.email = email = data[:email]

        raise Discourse::InvalidParameters.new(:email) if email.blank?

        # If the auth supplies a name / username, use those. Otherwise start with email.
        result.name = data[:name] || data[:email]
        result.username = data[:nickname] || data[:email]

        user_open_id = UserOpenId.find_by_url(identity_url)

        if !user_open_id && @opts[:trusted] && user = User.find_by_email(email)
            user_open_id = UserOpenId.create(url: identity_url , user_id: user.id, email: email, active: true)
        end

        result.user = user_open_id.try(:user)
        result.extra_data = {
            openid_url: identity_url,
            # note email may change by the time after_create_account runs
            email: email
        }
        
        # groups?

        result.email_valid = @opts[:trusted]

        result
    end

    def after_create_account(user, auth)
        
        Rails.logger.debug "Auth::OpenIdConnectAuthenticator :: after_create_account"
        
        data = auth[:extra_data]
        UserOpenId.create(
            user_id: user.id,
            url: data[:openid_url],
            email: data[:email],
            active: true
            # groups?
        )
    end


    def register_middleware(omniauth)
        
        Rails.logger.debug "Auth::OpenIdConnectAuthenticator :: register_middleware"
        
        omniauth.provider :openid_connect,
                      :setup => lambda { |env|
                            strategy = env["omniauth.strategy"]
                            strategy.options[:store] = OpenID::Store::Redis.new($redis)
                      },
                      :name => name,
                      :identifier => identifier,
                      :require => "omniauth-openid-connect"
    end
end


class ::OmniAuth::Strategies::OpenIDConnectBasic < ::OmniAuth::Strategies::OpenIDConnect
    option :name, "oidc_basic"
    info do
        {
            id: access_token['id']
        }
    end
end

class OpenIDConnectBasicAuthenticator < ::Auth::OpenIdConnectAuthenticator
    
    def register_middleware(omniauth)
        
        Rails.logger.debug "OpenIDConnectBasicAuthenticator :: register_middleware"
        
        omniauth.provider :openid_connect,
            name: 'oidc_basic',
            response_type: :code,
            scope: [:openid, :email, :profile, :address],
            client_options: lambda {|env|
                opts = env['omniauth.strategy'].options
                opts[:port] = 443
                opts[:scheme] = "https"
                opts[:identifier] = SiteSetting.oidc_client_id
                opts[:secret] = SiteSetting.oidc_client_secret
                opts[:discovery] = true
                opts[:issuer] = SiteSetting.oidc_issuer_url
                #opts[:authorize_options] = SiteSetting.oidc_authorize_options.split("|").map(&:to_sym)

                #if SiteSetting.oidc_send_auth_header?
                #    opts[:token_params] = {headers: {'Authorization' => basic_auth_header }}
                #end
            }
    end

    #def basic_auth_header
    #    "Basic " + Base64.strict_encode64("#{SiteSetting.oidc_client_id}:#{SiteSetting.oidc_client_secret}")
    #end

    def walk_path(fragment, segments)
        
        Rails.logger.debug "OpenIDConnectBasicAuthenticator :: walk_path"
        
        first_seg = segments[0]
        return if first_seg.blank? || fragment.blank?
        return nil unless fragment.is_a?(Hash)
        deref = fragment[first_seg] || fragment[first_seg.to_sym]

        return (deref.blank? || segments.size == 1) ? deref : walk_path(deref, segments[1..-1])
    end

    def json_walk(result, user_json, prop)
        
        Rails.logger.debug "OpenIDConnectBasicAuthenticator :: json_walk"
        
        path = SiteSetting.send("oidc_json_#{prop}_path")
        if path.present?
            segments = path.split('.')
            val = walk_path(user_json, segments)
            result[prop] = val if val.present?
        end
    end

    def log(info)
        Rails.logger.warn("OIDC Debugging: #{info}") if SiteSetting.oidc_debug_auth
    end

    def fetch_user_details(token, id)
        
        Rails.logger.debug "OpenIDConnectBasicAuthenticator :: fetch_user_details"
        
        user_json_url = SiteSetting.oidc_user_json_url.sub(':token', token.to_s).sub(':id', id.to_s)

        log("user_json_url: #{user_json_url}")

        user_json = JSON.parse(open(user_json_url, 'Authorization' => "Bearer #{token}" ).read)

        log("user_json: #{user_json}")

        result = {}
        if user_json.present?
            json_walk(result, user_json, :user_id)
            json_walk(result, user_json, :username)
            json_walk(result, user_json, :name)
            json_walk(result, user_json, :email)
        end

        result
    end

    def after_authenticate(auth)
        log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")

        Rails.logger.debug "OpenIDConnectBasicAuthenticator :: after_authenticate"
        
        result = Auth::Result.new
        token = auth['credentials']['token']
        user_details = fetch_user_details(token, auth['info'][:id])

        result.name = user_details[:name]
        result.username = user_details[:username]
        result.email = user_details[:email]
        result.email_valid = result.email.present? && SiteSetting.oidc_email_verified?

        current_info = ::PluginStore.get("oidc_basic", "oidc_basic_user_#{user_details[:user_id]}")
        if current_info
            result.user = User.where(id: current_info[:user_id]).first
        elsif SiteSetting.oidc_email_verified?
            result.user = User.where(email: Email.downcase(result.email)).first
            if result.user && user_details[:user_id]
                ::PluginStore.set("oidc_basic", "oidc_basic_user_#{user_details[:user_id]}", {user_id: result.user.id})
            end
        end

        result.extra_data = { oidc_basic_user_id: user_details[:user_id] }
        result
    end

    def after_create_account(user, auth)
        
        Rails.logger.debug "OpenIDConnectBasicAuthenticator :: after_create_account"
        
        ::PluginStore.set("oidc_basic", "oidc_basic_user_#{auth[:extra_data][:oidc_basic_user_id]}", {user_id: user.id })
    end
end

auth_provider title_setting: "oidc_button_title",
                            enabled_setting: "oidc_enabled",
                            authenticator: OpenIDConnectBasicAuthenticator.new('oidc_basic', 'OpenIDConnectBasic'),
                            message: "OpenID Connect"

register_css <<CSS

    button.btn-social.oidc_basic {
        background-color: #f8931d;
    }

CSS
