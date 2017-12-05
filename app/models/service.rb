class Service < ApplicationRecord
  belongs_to :user

  def client
    send("#{provider}_client") # metaprogramming
  end

  def facebook_client
    Koala::Facebook::API.new(access_token)
  end

  def access_token
    if expires_at? && expires_at <= Time.zone.now
      new_token_info = Koala::Facebook::OAuth.new.exchange_access_token_info(super)
      update(
        access_token: new_token_info["access_token"],
        expires_at: Time.zone.now + new_token_info["expires_in"]
      )
    end
    super
end
