require 'net/ldap'
require 'devise/strategies/authenticatable'

module Devise
  module Strategies
    class LdapAuthenticatable < Authenticatable
      def authenticate!
        if params[:user]
        ldap = Net::LDAP.new  :host => "nor-ldaps.ou.edu",
        :port => 636,
        :encryption => :simple_tls,
        :base => "OU=Accounts,DC=sooner,DC=net,DC=ou,DC=edu", 
        :auth => {
            :method => :simple,
            :username => email, 
            :password => password 
        }

        if ldap.bind
            user = User.find_by_email(email)
            if !user.nil?
              success!(user)
            else
              user = User.create(email: email, password: password, password_confirmation: password)
              success!(user)
            end
          else
            return fail(:invalid_login)
          end
        end
      end
      
      def email
        params[:user][:email]
      end

      def password
        params[:user][:password]
      end

    end
  end
end

Warden::Strategies.add(:ldap_authenticatable, Devise::Strategies::LdapAuthenticatable)