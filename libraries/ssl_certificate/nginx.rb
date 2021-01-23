require 'chef/version_constraint'

class Chef
  class Provider
    class SSLCertificate
      class Nginx < ::Chef::Provider::SSLCertificate
        def basedir
          '/var/www/acme'
        end

        def initialize(*args)
          super(*args)

          if node.automatic_attrs[:nginx][:version].is_a?(String)
            unless Chef::VersionConstraint.new(">= 1.10").include?(node.automatic_attrs[:nginx][:version])
              Chef::Log.warn("This provider has not been tested with nginx < 1.10")
            end
          end
        end

        def setup_challenge(authorization)
          challenge = authorization.http

          directory ::File.dirname(::File.join(basedir, challenge.filename)) do
            owner     node[:nginx][:user]
            group     node[:nginx][:user]
            mode      00755
            recursive true
          end

          file ::File.join(basedir, challenge.filename) do
            content challenge.file_content

            mode 00644
            owner node[:nginx][:user]
          end
        end

        def validate_challenge(authorization)
          authorization.http.request_validation
        end

        def teardown_challenge(authorization)
          challenge = authorization.http

          file ::File.join(basedir, challenge.filename) do
            action :delete
          end
        end
      end
    end
  end
end
