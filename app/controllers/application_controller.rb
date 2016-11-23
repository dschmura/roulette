class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  before_action :redirect_https, :cosign_uniqname
  
  private
  def cosign_uniqname
    @cosign_uniqname = request.headers.env.fetch('REMOTE_USER')
  end

  def redirect_https
    @ip = request.remote_ip
    redirect_to protocol: "https://" unless (request.ssl? || @ip.match(/127.0.0.1|::1/))
  end
end
