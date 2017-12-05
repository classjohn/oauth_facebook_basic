# Facebook Login II
* Service 모델을 분리하여 multiple provider 설정을 준비하기
* OAuth에 대해 <http://d2.naver.com/helloworld/24942>
---
## 0. Facebook developer
### 0. <https://developers.facebook.com> 로그인
### 1. 새 app을 만들고,
### 2. redirection url을 설정
- 테스트 서버일 경우, `http://localhost:3000/users/auth/facebook/callback`
- Devise & Omniauth가 미리 설정해준 redirect url : `rake routes`로 확인 가능

## 1. Rails 기본 세팅
### 0. `Gemfile`
```
gem 'devise'
gem 'omniauth-facebook'
```
### 1. Home#index 만들고 root 설정
```
rails g controller home index
```
`config/routes.rb`에 root 설정
```ruby
root 'home#index'
```
### 2. Devise `User` 생성
```
rails g devise:install
rails g devise User
```
### 3. `app/views/layouts/application.html.erb`에 로그인/로그아웃 view 추가
```ruby
<% if user_signed_in? %>
  <%= current_user.email %> | <%= link_to "로그아웃", destroy_user_session_path, method: :delete %>
<% else %>
  <%= link_to "로그인", new_user_session_path %>
<% end %>
```

## 2. OmniAuth 설정
### 0. User 모델에 omniauth 추가 `app/model/user.rb`
```
devise :database_authenticatable, :registerable,
       :recoverable, :rememberable, :trackable, :validatable, :omniauthable # omniauthable 추가
```
### 1. `config/secrets.yml`에 facebook app_id & app_secret 추가
```yaml
development:
  secret_key_base: ... # 아래에 facebook_app_id와 facebook_app_secret 추가
  facebook_app_id: # 여러분 app_id
  facebook_app_secret: # 여러분 app_secret
```

### 2. route 설정 `config/routes.rb`
```ruby
devise_for :users, controllers: { omniauth_callbacks: 'users/omniauth_callbacks'}
```

### 3. Devise `config/initializers/devise.rb`에 facebook omniauth 내용 추가
```ruby
config.omniauth :facebook, Rails.application.secrets.facebook_app_id, Rails.application.secrets.facebook_app_secret,
                scope: 'email' # scope 안에 내용 추가 가능, 예를 들어 scope: 'email, user_posts, name'
```
scope & permission :<https://developers.facebook.com/docs/facebook-login/permissions/>

## 3. omniauth callback을 위한 Controller 생성
### 0. `rake routes`로 자동 생성된 url 확인 후 명명 규칙에 따라 `app/controllers/users/omniauth_callbacks_controller.rb` 생성
```ruby
class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController

  def facebook
    p request.env['omniauth.auth']
    redirect_to root_path
  end

end
```
- 페이스북으로부터 날아온 정보를 콘솔에 출력
- OmniAuth는 **AuthHash** 라는 객체에 요청 정보를 저장/조작할 수 있게 한다. <https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema>
- **AuthHash** 를 잘 사용하는 것이 핵심
- User 및 서비스 별로 각각의 Auth 정보를 저장하기 위해 새로운 모델을 생성할거임

### 1. Service 모델 생성
- **AuthHash** 에서 날아온 **provider** (여기선 facebook) 관련 정보 및 해당 provider에서 관리하는 유저 정보들을 저장할 모델을 만든다.
```
rails g model Service user:references provider uid access_token access_token_secret refresh_token expires_at:datetime auth:text
```
하나씩 살펴보면,
- `provider` : oauth provider 여기서는 'facebook'
- `uid` :
- `access_token` : 해당 유저의 credential로 페이스북 데이터에 접근할 수 있게 인증하는 token
- `access_token_secret` : 가끔씩 이거에 secret도 달아두는 서비스가 있음 (페북도 option으로 있음)
- `refresh_token` : 새로 발행된 토큰
- `expires_at:datetime` : 서비스 마다 다르지만 토큰은 만료기한이 있음 (없는 것도 있음, like **Github**)
- `auth` : AuthHash를 집어 넣을 column

### 2. 로그인 로직 생성
- 날아온 정보와 일치하는 유저정보가 있는지 확인(있으면, 로그인)
- 없으면 새로 계정을 만든다.
```ruby
class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController

  def auth
    request.env['omniauth.auth'] # AuthHash를 return (auth라는 객체가 만들어져 사용할 수 있음)
  end

  def facebook
    service = Service.where(provider: auth.provider, uid: auth.uid).first

    if service.present?
      user = service.user
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
    sign_in_and_redirect user, event: authentication
    set_flash_message :notice, :success, kind: "Facebook"
  end

end
```

### 3. token refresh 해주기

```ruby
class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController

  def auth
    request.env['omniauth.auth'] # AuthHash를 return (auth라는 객체가 만들어져 사용할 수 있음)
  end

  def facebook
    service = Service.where(provider: auth.provider, uid: auth.uid).first

    if service.present?
      user = service.user
      service.update(
        expires_at: Time.at(auth.credentials.expires_at), # 새로 받아오면 만기기한도 업데이트 해주자
        access_token: auth_credentials.token
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
    sign_in_and_redirect user, event: authentication
    set_flash_message :notice, :success, kind: "Facebook"
  end

end
```
