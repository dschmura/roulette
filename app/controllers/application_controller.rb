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

  def ldap_full_name(uniqname = @cosign_uniqname)
    ldap = Net::LDAP.new :host => 'ldap.umich.edu',
      :port => 389,
    :auth => {
      :method => :anonymous
    }

    filter = Net::LDAP::Filter.eq("uid", uniqname)
    treebase = "dc=umich,dc=edu"
    attrs = ["displayname"]

    ldap.search(:base => treebase, :filter => filter,:attributes => attrs, :return_result => true) do |entry|
      @ldap_full_name = entry.displayname[0]
    end
  end
end