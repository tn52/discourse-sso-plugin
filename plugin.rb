require 'auth/oauth2_authenticator'
require 'omniauth-oauth2'

class HummingbirdAuthenticator < ::Auth::OAuth2Authenticator

  CLIENT_ID = '...'
  CLIENT_SECRET = '...'

  def register_middleware(omniauth)
    omniauth.provider :hummingbird, CLIENT_ID, CLIENT_SECRET
  end
end

class OmniAuth::Strategies::Hummingbird < OmniAuth::Strategies::OAuth2
  # Give your strategy a name.
  option :name, "hummingbird"

  # This is where you pass the options you would pass when
  # initializing your consumer from the OAuth gem.
  option :client_options, site: 'http://hummingbird.me'

  # These are called after authentication has succeeded. If
  # possible, you should try to set the UID without making
  # additional calls (if the user id is returned with the token
  # or as a URI parameter). This may not be possible with all
  # providers.
  uid { raw_info['id'].to_s }

  info do
    {
      :name => raw_info['name'],
      :email => raw_info['email']
    }
  end

  extra do
    {
      'raw_info' => raw_info
    }
  end

  def raw_info
    @raw_info ||= access_token.get('/oauth/me.json').parsed
  end
end

auth_provider :title => 'Sign in with Hummingbird account',
    :message => 'Log in using your Hummingbird account. (Make sure your popup blocker is disabled.)',
    :frame_width => 920,
    :frame_height => 800,
    :authenticator => HummingbirdAuthenticator.new('hummingbird', trusted: true,
      auto_create_account: true)
