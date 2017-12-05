class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def facebook
    service = Service.where(provider: auth.provider, uid: auth.uid).first

    if service.present?
      user = service.user
      service.update(
        expires_at: Time.at(auth.credentials.expires_at),
        access_token: auth.credentials.token
      )
    else
      user = User.create(
        email: auth.info.email,
        # name: auth.info.nam,
        password: Devise.friendly_token[0, 20]
      )

      user.services.create(
        provider: auth.provider,
        uid: auth.uid,
        expires_at: Time.at(auth.credentials.expires_at),
        access_token: auth.credentials.token
      )
    end

    sign_in_and_redirect user, event: :authenticate
    set_flash_message :notice, :success, kind: "Facebook"
  end

  def auth
    request.env['omniauth.auth']
  end
end
